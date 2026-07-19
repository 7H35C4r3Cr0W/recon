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
from oscprecon.modules import ftp as ftp_mod
from oscprecon.profile import Profile

_MANUAL_YAML = Path(ftp_mod.__file__).parent / "manual_commands.yaml"
_COMMAND_ROLE = Qt.ItemDataRole.UserRole


class FtpPanel(QWidget):
    recon_requested = Signal(str, int)  # (mode: full | anon, port)
    manual_requested = Signal(str)  # command

    def __init__(self) -> None:
        super().__init__()
        self._profile: Profile | None = None
        self._host_ip = ""  # a pivoted host's IP; "" = the entry target
        self._port = 21

        self._full = QPushButton("Run full FTP recon (bounded walk)")
        self._full.setStyleSheet(styles.accent_button())  # flagship Tier-1 action
        self._full.clicked.connect(lambda: self.recon_requested.emit("full", self._port))
        self._anon = QPushButton("Just list anonymous root")
        self._anon.clicked.connect(lambda: self.recon_requested.emit("anon", self._port))
        button_box = QGroupBox("Tier 1 — anonymous recon (read-only; never downloads)")
        button_layout = QVBoxLayout(button_box)
        for button in (self._full, self._anon):
            button_layout.addWidget(button)

        self._manual = QListWidget()
        self._manual.itemActivated.connect(self._on_manual_activated)
        self._manual.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._manual.customContextMenuRequested.connect(self._on_manual_menu)
        manual_box = QGroupBox("Manual follow-ups (Tier 2 — double-click to run; edit FILE/SUBDIR)")
        QVBoxLayout(manual_box).addWidget(self._manual)

        self._summary = QListWidget()
        summary_box = QGroupBox("Findings so far")
        QVBoxLayout(summary_box).addWidget(self._summary)

        intro = QLabel("FTP recon — anonymous enumeration only; download is a Tier-2 click.")
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

    def configure(self, service: DiscoveredService, host_ip: str = "") -> None:
        self._port = service.port
        self._host_ip = host_ip
        self._reload_manual()

    def set_running(self, running: bool) -> None:
        for button in (self._full, self._anon):
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
        # the manual templates write ftp://{target}/... — fold a non-default port into the host
        # authority so every follow-up hits the real port (curl would otherwise default to :21).
        ip = self._host_ip or target.ip
        host = ip if self._port == 21 else f"{ip}:{self._port}"
        for entry in manual_commands.load_manual_commands(_MANUAL_YAML):
            command = manual_commands.expand(entry.command, target=host, port=self._port)
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
