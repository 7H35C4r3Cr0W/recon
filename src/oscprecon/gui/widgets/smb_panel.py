from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QGroupBox,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from oscprecon import manual_commands
from oscprecon.gui.theme import styles
from oscprecon.models import DiscoveredService
from oscprecon.modules import smb as smb_mod
from oscprecon.profile import Profile

_MANUAL_YAML = Path(smb_mod.__file__).parent / "manual_commands.yaml"
_COMMAND_ROLE = Qt.ItemDataRole.UserRole


class SmbPanel(QWidget):
    recon_requested = Signal(str)  # mode: full | null | guest | shares
    manual_requested = Signal(str)  # command

    def __init__(self) -> None:
        super().__init__()
        self._profile: Profile | None = None

        self._full = QPushButton("Run full SMB recon")
        self._full.setStyleSheet(styles.accent_button())  # flagship Tier-1 action
        self._full.clicked.connect(lambda: self.recon_requested.emit("full"))
        self._null = QPushButton("Just check null session")
        self._null.clicked.connect(lambda: self.recon_requested.emit("null"))
        self._guest = QPushButton("Just check guest")
        self._guest.clicked.connect(lambda: self.recon_requested.emit("guest"))
        self._shares = QPushButton("Just enumerate shares")
        self._shares.clicked.connect(lambda: self.recon_requested.emit("shares"))
        button_box = QGroupBox("Tier 1 — automatic recon")
        button_layout = QVBoxLayout(button_box)
        for button in (self._full, self._null, self._guest, self._shares):
            button_layout.addWidget(button)

        self._manual = QListWidget()
        self._manual.itemActivated.connect(self._on_manual_activated)
        self._manual.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._manual.customContextMenuRequested.connect(self._on_manual_menu)
        manual_box = QGroupBox(
            "Manual follow-ups (Tier 2 — double-click to run; right-click to copy)"
        )
        manual_layout = QVBoxLayout(manual_box)
        manual_layout.addWidget(self._manual)

        self._summary = QListWidget()
        summary_box = QGroupBox("Findings so far")
        summary_layout = QVBoxLayout(summary_box)
        summary_layout.addWidget(self._summary)

        intro = QLabel("SMB recon — Tier framing is enforced (§11); Tier-3 is never shown.")
        intro.setWordWrap(True)
        # single column keeps the panel narrow (no sideways scroll); the tool panel scrolls
        # vertically to reach the boxes on a short window.
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addWidget(button_box)
        layout.addWidget(manual_box, stretch=1)
        layout.addWidget(summary_box, stretch=1)

    def set_profile(self, profile: Profile) -> None:
        self._profile = profile
        self._reload_manual()

    def configure(self, service: DiscoveredService) -> None:
        self._reload_manual()

    def set_running(self, running: bool) -> None:
        for button in (self._full, self._null, self._guest, self._shares):
            button.setEnabled(not running)

    def set_summary(self, lines: list[str]) -> None:
        self._summary.clear()
        for line in lines:
            self._summary.addItem(line)

    def _reload_manual(self) -> None:
        self._manual.clear()
        if self._profile is None:
            return
        target = self._profile.target
        # pre-fill {user}/{password}/{domain} from the first collected password credential so the
        # netexec/CME follow-ups come ready to run (the user still reviews before running).
        cred = next(
            (c for c in self._profile.credentials() if c.secret_type == "password"), None
        )
        user = cred.username if cred is not None else ""
        password = cred.secret if cred is not None else ""
        domain = (cred.domain if cred is not None and cred.domain else "") or target.hostname or ""
        for entry in manual_commands.load_manual_commands(_MANUAL_YAML):
            command = manual_commands.expand(
                entry.command, target=target.ip, domain=domain, user=user, password=password
            )
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
        forward = menu.addAction("Copy (forward //)")
        backslash = menu.addAction("Copy (backslash \\\\)")
        escaped = menu.addAction("Copy (bash-escaped)")
        chosen = menu.exec(viewport.mapToGlobal(pos))
        clipboard = QGuiApplication.clipboard()
        if clipboard is None or chosen is None:
            return
        if chosen is forward:
            clipboard.setText(command)
        elif chosen is backslash:
            clipboard.setText(smb_mod.to_backslash_command(command))
        elif chosen is escaped:
            clipboard.setText(smb_mod.to_escaped_command(command))
