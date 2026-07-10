from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem

from oscprecon.models import DiscoveredService, Proto

_SERVICE_ROLE = Qt.ItemDataRole.UserRole


class ServiceTree(QTreeWidget):
    service_selected = Signal(object)

    def __init__(self) -> None:
        super().__init__()
        self.setHeaderLabels(["Port", "Service", "Product"])
        self.setColumnWidth(0, 90)
        self.setColumnWidth(1, 120)
        self.currentItemChanged.connect(self._on_current_changed)

    def populate(self, services: list[DiscoveredService]) -> None:
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
