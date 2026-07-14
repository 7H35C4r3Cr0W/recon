from __future__ import annotations

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPaintEvent
from PySide6.QtWidgets import QMenu, QTreeWidget, QTreeWidgetItem

from oscprecon.models import DiscoveredService, Proto

_SERVICE_ROLE = Qt.ItemDataRole.UserRole

# TCP vs UDP get distinct port colours so the two transports read apart at a glance (mirrors the
# graph's TCP-blue / UDP-green language). Chosen for legibility on both the light and dark tree.
_PROTO_COLOR = {Proto.TCP: QColor("#4a7fb5"), Proto.UDP: QColor("#4f8a5f")}


class ServiceTree(QTreeWidget):
    service_selected = Signal(object)
    treat_as_http = Signal(object)

    def __init__(self) -> None:
        super().__init__()
        self._signature: tuple[tuple[int, str, str, str, str], ...] = ()
        # why: an empty QTreeWidget is just a blank box — with no message the user can't tell a
        # not-scanned-yet host from a 0-open-ports one from a scan-in-progress. This text is painted
        # over the empty viewport and the MainWindow updates it as the scan state changes.
        self._empty_message = "No services yet.\nClick “Run Full Recon” to scan the target."
        self.setAccessibleName("Discovered services")
        self.setHeaderLabels(["Port", "Service", "Product"])
        self.setColumnWidth(0, 110)
        self.setColumnWidth(1, 120)
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

    def populate(self, services: list[DiscoveredService], *, force: bool = False) -> None:
        # why: skip the clear()+rebuild when the service set is unchanged — a rebuild drops the
        # user's current selection, and background service recon (which never adds ports) would
        # otherwise churn it on every completion. force=True on a genuine profile switch, where a
        # coincidentally-identical signature must still rebind the items to the new profile.
        signature = tuple(
            (s.port, s.proto.value, s.service, s.product, s.version) for s in services
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
        self.expandAll()

    def _on_current_changed(
        self, current: QTreeWidgetItem | None, previous: QTreeWidgetItem | None
    ) -> None:
        service = current.data(0, _SERVICE_ROLE) if current is not None else None
        self.service_selected.emit(service if isinstance(service, DiscoveredService) else None)
