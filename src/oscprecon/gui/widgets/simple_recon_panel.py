from __future__ import annotations

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from oscprecon import manual_commands
from oscprecon.gui.simple_recon import SimpleReconSpec
from oscprecon.models import DiscoveredService
from oscprecon.profile import Profile

_COMMAND_ROLE = Qt.ItemDataRole.UserRole


class SimpleReconPanel(QWidget):
    """One panel for any read-only single-shape module (nfs/snmp/tftp/netbios/ike/ntp/smtp)."""

    recon_requested = Signal(str, int)  # module name, discovered service port
    manual_requested = Signal(str)  # command

    def __init__(self, spec: SimpleReconSpec) -> None:
        super().__init__()
        self._spec = spec
        self._profile: Profile | None = None
        self._port = 0

        self._recon = QPushButton(spec.label)
        self._recon.clicked.connect(lambda: self.recon_requested.emit(spec.module, self._port))
        button_box = QGroupBox(
            "Tier 1 — read-only recon (streams to the output pane + findings.json)"
        )
        QVBoxLayout(button_box).addWidget(self._recon)

        self._manual = QListWidget()
        self._manual.itemActivated.connect(self._on_manual_activated)
        self._manual.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._manual.customContextMenuRequested.connect(self._on_manual_menu)
        manual_box = QGroupBox("Manual follow-ups (Tier 2 — double-click; edit literals first)")
        QVBoxLayout(manual_box).addWidget(self._manual)

        self._summary = QListWidget()
        summary_box = QGroupBox("Findings so far")
        QVBoxLayout(summary_box).addWidget(self._summary)

        left = QVBoxLayout()
        left.addWidget(button_box)
        left.addWidget(summary_box, stretch=1)
        top = QHBoxLayout()
        top.addLayout(left, stretch=1)
        top.addWidget(manual_box, stretch=1)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(spec.intro))
        layout.addLayout(top, stretch=1)

    def set_profile(self, profile: Profile) -> None:
        self._profile = profile
        self._reload_manual()

    def configure(self, service: DiscoveredService) -> None:
        self._port = service.port
        self._reload_manual()

    def set_running(self, running: bool) -> None:
        self._recon.setEnabled(not running)

    def set_summary(self, lines: list[str]) -> None:
        self._summary.clear()
        for line in lines:
            self._summary.addItem(line)

    def _reload_manual(self) -> None:
        self._manual.clear()
        if self._profile is None:
            return
        target = self._profile.target
        for entry in manual_commands.load_manual_commands(self._spec.manual_yaml):
            command = manual_commands.expand(entry.command, target=target.ip, port=self._port)
            item = QListWidgetItem(f"{entry.description}\n    {command}")
            item.setData(_COMMAND_ROLE, command)
            self._manual.addItem(item)

    def _on_manual_activated(self, item: QListWidgetItem) -> None:
        command = item.data(_COMMAND_ROLE)
        if isinstance(command, str):
            self.manual_requested.emit(command)

    def _on_manual_menu(self, pos: QPoint) -> None:
        item = self._manual.currentItem()
        if item is None:
            return
        command = item.data(_COMMAND_ROLE)
        if not isinstance(command, str):
            return
        viewport = self._manual.viewport()
        if viewport is None:
            return
        menu = QMenu(self)
        copy = menu.addAction("Copy command")
        chosen = menu.exec(viewport.mapToGlobal(pos))
        clipboard = QGuiApplication.clipboard()
        if chosen is copy and clipboard is not None:
            clipboard.setText(command)
