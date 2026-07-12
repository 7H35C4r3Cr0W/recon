from __future__ import annotations

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtWidgets import QMenu, QTreeWidget, QTreeWidgetItem

from oscprecon.models import DiscoveredService, Proto

_SERVICE_ROLE = Qt.ItemDataRole.UserRole


class ServiceTree(QTreeWidget):
    service_selected = Signal(object)
    treat_as_http = Signal(object)

    def __init__(self) -> None:
        super().__init__()
        self._signature: tuple[tuple[int, str, str, str, str], ...] = ()
        self.setHeaderLabels(["Port", "Service", "Product"])
        self.setColumnWidth(0, 90)
        self.setColumnWidth(1, 120)
        self.currentItemChanged.connect(self._on_current_changed)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_context_menu)

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
            for service in members:
                product = f"{service.product} {service.version}".strip()
                item = QTreeWidgetItem(
                    parent, [f"{service.port}/{service.proto.value}", service.service, product]
                )
                item.setData(0, _SERVICE_ROLE, service)
        self.expandAll()

    def _on_current_changed(
        self, current: QTreeWidgetItem | None, previous: QTreeWidgetItem | None
    ) -> None:
        service = current.data(0, _SERVICE_ROLE) if current is not None else None
        self.service_selected.emit(service if isinstance(service, DiscoveredService) else None)
