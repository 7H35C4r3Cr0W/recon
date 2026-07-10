from __future__ import annotations

from PySide6.QtWidgets import QGroupBox, QLabel, QListWidget, QVBoxLayout, QWidget

from oscprecon.models import DiscoveredService
from oscprecon.references import ServiceRef


class ReferencePane(QWidget):
    def __init__(self) -> None:
        super().__init__()

        self._label = QLabel("Select a service to see references.")
        self._label.setWordWrap(True)
        self._link = QLabel("")
        self._link.setWordWrap(True)
        self._link.setOpenExternalLinks(True)
        self._placeholder = QLabel("HackTricks page renders inline in chunk 5.")
        self._placeholder.setStyleSheet("color: gray;")

        hacktricks_box = QGroupBox("HackTricks")
        hacktricks_layout = QVBoxLayout(hacktricks_box)
        hacktricks_layout.addWidget(self._label)
        hacktricks_layout.addWidget(self._link)
        hacktricks_layout.addWidget(self._placeholder)
        hacktricks_layout.addStretch(1)

        self._exploits = QListWidget()
        exploits_box = QGroupBox("Exploit-DB")
        exploits_layout = QVBoxLayout(exploits_box)
        exploits_layout.addWidget(self._exploits)

        layout = QVBoxLayout(self)
        layout.addWidget(hacktricks_box, stretch=2)
        layout.addWidget(exploits_box, stretch=1)

    def show_service(self, service: DiscoveredService | None, ref: ServiceRef | None) -> None:
        self._exploits.clear()
        if service is None or ref is None:
            self._label.setText("No reference mapping for this service.")
            self._link.setText("")
            return
        self._label.setText(f"{ref.label} — {service.port}/{service.proto.value}")
        self._link.setText(f'<a href="{ref.hacktricks}">{ref.hacktricks}</a>')
