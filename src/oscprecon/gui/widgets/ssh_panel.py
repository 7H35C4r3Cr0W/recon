from __future__ import annotations

from pathlib import Path

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
from oscprecon.models import DiscoveredService
from oscprecon.modules import ssh as ssh_mod
from oscprecon.profile import Profile

_MANUAL_YAML = Path(ssh_mod.__file__).parent / "manual_commands.yaml"
_COMMAND_ROLE = Qt.ItemDataRole.UserRole


class SshPanel(QWidget):
    recon_requested = Signal(int)  # port
    manual_requested = Signal(str)  # command

    def __init__(self) -> None:
        super().__init__()
        self._profile: Profile | None = None
        self._port = 22

        self._recon = QPushButton("Run full SSH recon (banner, algos, host keys, auth methods)")
        self._recon.clicked.connect(lambda: self.recon_requested.emit(self._port))
        button_box = QGroupBox("Tier 1 — SSH fingerprint (read-only; no login attempted)")
        QVBoxLayout(button_box).addWidget(self._recon)

        self._manual = QListWidget()
        self._manual.itemActivated.connect(self._on_manual_activated)
        self._manual.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._manual.customContextMenuRequested.connect(self._on_manual_menu)
        manual_box = QGroupBox("Manual follow-ups (Tier 2 — double-click; edit USER/KEYFILE)")
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
        layout.addWidget(
            QLabel("SSH recon — fingerprint only; single logins are Tier-2 manual follow-ups.")
        )
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
        # ssh uses `-p PORT user@host`, not host:port — keep {target} a bare host and let {port}
        # carry the port into every template (both the nmap and the ssh follow-ups).
        for entry in manual_commands.load_manual_commands(_MANUAL_YAML):
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
