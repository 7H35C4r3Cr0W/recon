from __future__ import annotations

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPaintEvent
from PySide6.QtWidgets import QHeaderView, QMenu, QTreeWidget, QTreeWidgetItem

from oscprecon.models import DiscoveredHost, DiscoveredService, Proto

_SERVICE_ROLE = Qt.ItemDataRole.UserRole
_HOST_COLOR = QColor("#3f8fb0")  # matches the graph's pivoted-host teal
_SUBNET_COLOR = QColor("#8a8fa0")

# TCP vs UDP get distinct port colours so the two transports read apart at a glance (mirrors the
# graph's TCP-blue / UDP-green language). Chosen for legibility on both the light and dark tree.
_PROTO_COLOR = {Proto.TCP: QColor("#4a7fb5"), Proto.UDP: QColor("#4f8a5f")}


class ServiceTree(QTreeWidget):
    service_selected = Signal(object)
    treat_as_http = Signal(object)

    def __init__(self) -> None:
        super().__init__()
        self._signature: tuple[object, ...] = ()
        # why: an empty QTreeWidget is just a blank box — with no message the user can't tell a
        # not-scanned-yet host from a 0-open-ports one from a scan-in-progress. This text is painted
        # over the empty viewport and the MainWindow updates it as the scan state changes.
        self._empty_message = "No services yet.\nClick “Run Full Recon” to scan the target."
        self.setAccessibleName("Discovered services")
        self.setHeaderLabels(["Port / host", "Service", "Product"])
        # size every column to its content so a host's ip/name (col 0, indented 3 levels under
        # subnet → host) never truncates to "10.10…"; the tree scrolls horizontally if the sum
        # exceeds a narrow pane, which never hides text the way a clipped fixed column does.
        header = self.header()
        if header is not None:
            for col in range(3):
                header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
            header.setStretchLastSection(False)
        self.currentItemChanged.connect(self._on_current_changed)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_context_menu)

    def set_empty_message(self, text: str) -> None:
        self._empty_message = text
        viewport = self.viewport()
        if viewport is not None:
            viewport.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        super().paintEvent(event)
        if self.topLevelItemCount() > 0:
            return
        viewport = self.viewport()
        if viewport is None:
            return
        painter = QPainter(viewport)
        painter.setPen(self.palette().placeholderText().color())
        rect = viewport.rect().adjusted(16, 16, -16, -16)
        flags = Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap
        painter.drawText(rect, int(flags), self._empty_message)
        painter.end()

    def _on_context_menu(self, pos: QPoint) -> None:
        item = self.itemAt(pos)
        service = item.data(0, _SERVICE_ROLE) if item is not None else None
        if not isinstance(service, DiscoveredService):
            return
        menu = QMenu(self)
        action = menu.addAction("Treat as HTTP")
        if menu.exec(self.viewport().mapToGlobal(pos)) is action:
            self.treat_as_http.emit(service)

    def populate(
        self,
        services: list[DiscoveredService],
        hosts: list[DiscoveredHost] | None = None,
        *,
        force: bool = False,
    ) -> None:
        # why: skip the clear()+rebuild when the service set is unchanged — a rebuild drops the
        # user's current selection, and background service recon (which never adds ports) would
        # otherwise churn it on every completion. force=True on a genuine profile switch, where a
        # coincidentally-identical signature must still rebind the items to the new profile.
        hosts = hosts or []
        signature: tuple[object, ...] = (
            tuple((s.port, s.proto.value, s.service, s.product, s.version) for s in services),
            tuple(
                (
                    h.ip,
                    h.hostname,
                    h.subnet,
                    h.pivot_source,
                    tuple((v.port, v.proto.value) for v in h.services),
                )
                for h in hosts
            ),
        )
        if not force and signature == self._signature:
            return
        self._signature = signature
        self.clear()
        for proto in (Proto.TCP, Proto.UDP):
            members = sorted((s for s in services if s.proto == proto), key=lambda s: s.port)
            if not members:
                continue
            parent = QTreeWidgetItem(self, [f"{proto.value.upper()} ({len(members)})", "", ""])
            header_font = parent.font(0)
            header_font.setWeight(QFont.Weight.DemiBold)
            parent.setFont(0, header_font)
            for service in members:
                product = f"{service.product} {service.version}".strip()
                item = QTreeWidgetItem(
                    parent, [f"{service.port}/{service.proto.value}", service.service, product]
                )
                item.setForeground(0, QBrush(_PROTO_COLOR[proto]))
                item.setData(0, _SERVICE_ROLE, service)
        self._add_pivot_hosts(hosts)
        self.expandAll()

    def _add_pivot_hosts(self, hosts: list[DiscoveredHost]) -> None:
        # pivoted hosts (found by scanning a /24 across the tunnel) grouped by subnet, so the whole
        # engagement reads as one organised tree in the recon tab — mirrors the graph's spider-web.
        if not hosts:
            return
        by_subnet: dict[str, list[DiscoveredHost]] = {}
        for host in hosts:
            by_subnet.setdefault(host.subnet or "unknown", []).append(host)
        root = QTreeWidgetItem(self, [f"Pivoted networks ({len(hosts)})", "", ""])
        root_font = root.font(0)
        root_font.setWeight(QFont.Weight.DemiBold)
        root.setFont(0, root_font)
        for subnet in sorted(by_subnet):
            members = sorted(by_subnet[subnet], key=lambda h: h.ip)
            subnet_item = QTreeWidgetItem(root, [f"{subnet} ({len(members)})", "", ""])
            subnet_item.setForeground(0, QBrush(_SUBNET_COLOR))
            for host in members:
                # col 0 = ip/name (kept short so it doesn't crowd out the entry services' names);
                # os in col 1, pivot source in col 2 (the host's otherwise-empty Product column).
                name = f"{host.ip} ({host.hostname})" if host.hostname else host.ip
                via = f"← {host.pivot_source}" if host.pivot_source else ""
                host_item = QTreeWidgetItem(subnet_item, [name, host.os_guess, via])
                host_item.setForeground(0, QBrush(_HOST_COLOR))
                for service in sorted(host.services, key=lambda s: (s.proto.value, s.port)):
                    product = f"{service.product} {service.version}".strip()
                    svc_item = QTreeWidgetItem(
                        host_item,
                        [f"{service.port}/{service.proto.value}", service.service, product],
                    )
                    svc_item.setForeground(0, QBrush(_PROTO_COLOR.get(service.proto, _HOST_COLOR)))
                    svc_item.setData(0, _SERVICE_ROLE, service)

    def _on_current_changed(
        self, current: QTreeWidgetItem | None, previous: QTreeWidgetItem | None
    ) -> None:
        service = current.data(0, _SERVICE_ROLE) if current is not None else None
        self.service_selected.emit(service if isinstance(service, DiscoveredService) else None)
