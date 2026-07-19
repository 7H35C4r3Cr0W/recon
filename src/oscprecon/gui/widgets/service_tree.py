from __future__ import annotations

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPaintEvent
from PySide6.QtWidgets import QHeaderView, QMenu, QTreeWidget, QTreeWidgetItem

from oscprecon.models import DiscoveredHost, DiscoveredService, Proto, Target

_SERVICE_ROLE = Qt.ItemDataRole.UserRole
_HOST_ROLE = Qt.ItemDataRole.UserRole + 1  # a pivoted-host row -> its DiscoveredHost
_SUBNET_ROLE = Qt.ItemDataRole.UserRole + 2  # a subnet row -> its CIDR string
_KEY_ROLE = Qt.ItemDataRole.UserRole + 3  # a stable key for expand/collapse persistence
_HOST_COLOR = QColor("#3f8fb0")  # matches the graph's pivoted-host teal
_SUBNET_COLOR = QColor("#8a8fa0")

# TCP vs UDP get distinct port colours so the two transports read apart at a glance (mirrors the
# graph's TCP-blue / UDP-green language). Chosen for legibility on both the light and dark tree.
_PROTO_COLOR = {Proto.TCP: QColor("#4a7fb5"), Proto.UDP: QColor("#4f8a5f")}


class ServiceTree(QTreeWidget):
    service_selected = Signal(object)  # DiscoveredService | None
    host_selected = Signal(object)  # DiscoveredHost | None (a pivoted-host row was clicked)
    treat_as_http = Signal(object)  # DiscoveredService
    scan_host_requested = Signal(str)  # ip — re-scan a pivoted host deeper
    remove_host_requested = Signal(str)  # ip — drop one host from the topology
    remove_subnet_requested = Signal(str)  # cidr — drop a whole /24

    def __init__(self) -> None:
        super().__init__()
        self._signature: tuple[object, ...] = ()
        # collapse/expand state persists across the clear()+rebuild a streaming scan triggers, keyed
        # by a stable per-node string, so a subnet the user folded shut stays shut as hosts arrive.
        self._collapsed: set[str] = set()
        self._restoring = False  # suppress the collapse/expand signals during programmatic restore
        # why: an empty QTreeWidget is just a blank box — with no message the user can't tell a
        # not-scanned-yet host from a 0-open-ports one from a scan-in-progress. This text is painted
        # over the empty viewport and the MainWindow updates it as the scan state changes.
        self._empty_message = "No services yet.\nClick Run Recon (or its ▾ for scan options)."
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
        self.itemExpanded.connect(self._on_expanded)
        self.itemCollapsed.connect(self._on_collapsed)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_context_menu)

    def reset_view_state(self) -> None:
        # a fresh project: forget the previous one's collapse state so a subnet folded shut in
        # project A doesn't come up folded in project B just because it shares a CIDR.
        self._collapsed.clear()

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

    # --- expand/collapse persistence ---
    def _on_expanded(self, item: QTreeWidgetItem) -> None:
        if self._restoring:
            return
        key = item.data(0, _KEY_ROLE)
        if isinstance(key, str):
            self._collapsed.discard(key)

    def _on_collapsed(self, item: QTreeWidgetItem) -> None:
        if self._restoring:
            return
        key = item.data(0, _KEY_ROLE)
        if isinstance(key, str):
            self._collapsed.add(key)

    def _apply_expansion(self) -> None:
        # a keyed node expands unless the user folded it shut before (default = expanded, so new
        # nodes open). Top-down so a parent is set before its children.
        self._restoring = True

        def walk(item: QTreeWidgetItem | None) -> None:
            if item is None:
                return
            key = item.data(0, _KEY_ROLE)
            if isinstance(key, str):
                item.setExpanded(key not in self._collapsed)
            for i in range(item.childCount()):
                walk(item.child(i))

        for i in range(self.topLevelItemCount()):
            walk(self.topLevelItem(i))
        self._restoring = False

    def _on_context_menu(self, pos: QPoint) -> None:
        item = self.itemAt(pos)
        if item is None:
            return
        host = item.data(0, _HOST_ROLE)
        subnet = item.data(0, _SUBNET_ROLE)
        service = item.data(0, _SERVICE_ROLE)
        menu = QMenu(self)
        viewport = self.viewport()
        if viewport is None:
            return
        globalpos = viewport.mapToGlobal(pos)
        if isinstance(host, DiscoveredHost):
            act_scan = menu.addAction("Scan this host…")
            act_remove = menu.addAction("Remove host from topology")
            chosen = menu.exec(globalpos)
            if chosen is act_scan:
                self.scan_host_requested.emit(host.ip)
            elif chosen is act_remove:
                self.remove_host_requested.emit(host.ip)
            return
        if isinstance(subnet, str):
            n = item.childCount()
            act_remove = menu.addAction(f"Remove subnet ({n} host{'s' if n != 1 else ''})…")
            if menu.exec(globalpos) is act_remove:
                self.remove_subnet_requested.emit(subnet)
            return
        # "Treat as HTTP" probes the ENTRY target — only offer it for the entry host's services, not
        # a pivoted host's (that would probe the wrong ip). Early-out keeps menu-add before exec.
        if not (isinstance(service, DiscoveredService) and not self._under_host(item)):
            return
        act_http = menu.addAction("Treat as HTTP")
        if menu.exec(globalpos) is act_http:
            self.treat_as_http.emit(service)

    @staticmethod
    def _under_host(item: QTreeWidgetItem) -> bool:
        parent = item.parent()
        while parent is not None:
            if isinstance(parent.data(0, _HOST_ROLE), DiscoveredHost):
                return True
            parent = parent.parent()
        return False

    def selected_service_host_ip(self) -> str:
        # the IP the CURRENT service belongs to: a pivoted host's IP (walk up to its host row) or ""
        # for an entry-target service. Lets the tool panels build commands against the right host
        # instead of always the entry box.
        item = self.currentItem()
        parent = item.parent() if item is not None else None
        while parent is not None:
            host = parent.data(0, _HOST_ROLE)
            if isinstance(host, DiscoveredHost):
                return host.ip
            parent = parent.parent()
        return ""

    def populate(
        self,
        services: list[DiscoveredService],
        hosts: list[DiscoveredHost] | None = None,
        *,
        target: Target | None = None,
        force: bool = False,
    ) -> None:
        # why: skip the clear()+rebuild when the service set is unchanged — a rebuild drops the
        # user's current selection, and background service recon (which never adds ports) would
        # otherwise churn it on every completion. force=True on a genuine profile switch, where a
        # coincidentally-identical signature must still rebind the items to the new profile.
        hosts = hosts or []
        # the signature must include EVERY field the tree renders, else a deeper rescan that only
        # enriches an existing row (fills a pivot host's product/OS on the same port set) yields an
        # identical signature and the early-return leaves the tree stale. Track os_guess for the
        # entry + each host, and full service detail (service/product/version) for pivot hosts. [#9]
        signature: tuple[object, ...] = (
            (target.ip, target.hostname, target.os_guess) if target is not None else None,
            tuple((s.port, s.proto.value, s.service, s.product, s.version) for s in services),
            tuple(
                (
                    h.ip,
                    h.hostname,
                    h.subnet,
                    h.pivot_source,
                    h.os_guess,
                    tuple(
                        (v.port, v.proto.value, v.service, v.product, v.version) for v in h.services
                    ),
                )
                for h in hosts
            ),
        )
        if not force and signature == self._signature:
            return
        self._signature = signature
        self.clear()
        # The entry host's services sit under an IP-labelled header (not a bare "TCP (n)"), so the
        # target IP/hostname is always visible at the top — consistent with the pivoted-host rows.
        entry_parent: QTreeWidget | QTreeWidgetItem = self
        if target is not None and services:
            name = f"{target.ip} ({target.hostname})" if target.hostname else target.ip
            entry = QTreeWidgetItem(self, [name, target.os_guess or "", "entry / pivot"])
            entry.setForeground(0, QBrush(_HOST_COLOR))
            entry.setData(0, _KEY_ROLE, "entry")
            entry_font = entry.font(0)
            entry_font.setWeight(QFont.Weight.DemiBold)
            entry.setFont(0, entry_font)
            entry_parent = entry
        for proto in (Proto.TCP, Proto.UDP):
            members = sorted((s for s in services if s.proto == proto), key=lambda s: s.port)
            if not members:
                continue
            parent = QTreeWidgetItem(
                entry_parent, [f"{proto.value.upper()} ({len(members)})", "", ""]
            )
            parent.setData(0, _KEY_ROLE, f"g:{proto.value}")
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
        self._apply_expansion()

    def _add_pivot_hosts(self, hosts: list[DiscoveredHost]) -> None:
        # pivoted hosts (found by scanning a /24 across the tunnel) grouped by subnet, so the whole
        # engagement reads as one organised tree in the recon tab — mirrors the graph's spider-web.
        if not hosts:
            return
        by_subnet: dict[str, list[DiscoveredHost]] = {}
        for host in hosts:
            by_subnet.setdefault(host.subnet or "unknown", []).append(host)
        root = QTreeWidgetItem(self, [f"Pivoted networks ({len(hosts)})", "", ""])
        root.setData(0, _KEY_ROLE, "pivot-root")
        root_font = root.font(0)
        root_font.setWeight(QFont.Weight.DemiBold)
        root.setFont(0, root_font)
        for subnet in sorted(by_subnet):
            members = sorted(by_subnet[subnet], key=lambda h: h.ip)
            subnet_item = QTreeWidgetItem(root, [f"{subnet} ({len(members)})", "", ""])
            subnet_item.setForeground(0, QBrush(_SUBNET_COLOR))
            subnet_item.setData(0, _SUBNET_ROLE, subnet)
            subnet_item.setData(0, _KEY_ROLE, f"n:{subnet}")
            for host in members:
                # col 0 = ip/name (kept short so it doesn't crowd out the entry services' names);
                # os in col 1, pivot source in col 2 (the host's otherwise-empty Product column).
                name = f"{host.ip} ({host.hostname})" if host.hostname else host.ip
                via = f"← {host.pivot_source}" if host.pivot_source else ""
                host_item = QTreeWidgetItem(subnet_item, [name, host.os_guess, via])
                host_item.setForeground(0, QBrush(_HOST_COLOR))
                host_item.setData(0, _HOST_ROLE, host)
                host_item.setData(0, _KEY_ROLE, f"h:{host.ip}")
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
        host = current.data(0, _HOST_ROLE) if current is not None else None
        self.service_selected.emit(service if isinstance(service, DiscoveredService) else None)
        self.host_selected.emit(host if isinstance(host, DiscoveredHost) else None)
