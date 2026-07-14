from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
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
from oscprecon.modules import ldap as ldap_mod
from oscprecon.profile import Profile

_MANUAL_YAML = Path(ldap_mod.__file__).parent / "manual_commands.yaml"
_COMMAND_ROLE = Qt.ItemDataRole.UserRole


class LdapPanel(QWidget):
    recon_requested = Signal(str, int)  # (basedn, port)
    manual_requested = Signal(str)  # command
    validation_failed = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self._profile: Profile | None = None
        self._port = 389

        self._basedn = QLineEdit()
        self._basedn.setPlaceholderText("base DN (e.g. DC=example,DC=htb) — blank = discover")
        self._basedn.textChanged.connect(self._reload_manual)
        form = QFormLayout()
        form.addRow("Base DN:", self._basedn)

        self._recon = QPushButton("Run full LDAP recon (root DSE + anonymous users)")
        self._recon.setStyleSheet(styles.accent_button())  # flagship Tier-1 action
        self._recon.clicked.connect(self._on_recon)
        button_box = QGroupBox("Tier 1 — anonymous LDAP recon (read-only, bounded)")
        box_layout = QVBoxLayout(button_box)
        box_layout.addLayout(form)
        box_layout.addWidget(self._recon)

        self._manual = QListWidget()
        self._manual.itemActivated.connect(self._on_manual_activated)
        self._manual.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._manual.customContextMenuRequested.connect(self._on_manual_menu)
        manual_box = QGroupBox("Manual follow-ups (Tier 2 — double-click; edit USER/PASSWORD)")
        QVBoxLayout(manual_box).addWidget(self._manual)

        self._summary = QListWidget()
        summary_box = QGroupBox("Findings so far")
        QVBoxLayout(summary_box).addWidget(self._summary)

        intro = QLabel(
            "LDAP recon — anonymous root DSE + bounded user enumeration; binds are Tier-2."
        )
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
        # why: seed the base DN from the hostname only when empty, so a scan-end refresh can't
        # clobber a value the user typed.
        if not self._basedn.text().strip():
            derived = ldap_mod.domain_to_basedn(profile.target.hostname)
            if derived:
                self._basedn.setText(derived)
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

    def _on_recon(self) -> None:
        raw = self._basedn.text().strip()
        if raw and ldap_mod.sanitize_basedn(raw) is None:
            self.validation_failed.emit(f"invalid base DN: {raw!r}")
            return
        self.recon_requested.emit(raw, self._port)

    def _reload_manual(self) -> None:
        self._manual.clear()
        if self._profile is None:
            return
        target = self._profile.target
        # why: {basedn} is interpolated into a runnable ldapsearch command, so sanitize it (drop it
        # if it isn't DN-syntax) before it reaches the command line — never trust the raw field.
        basedn = ldap_mod.sanitize_basedn(self._basedn.text()) or ""
        for entry in manual_commands.load_manual_commands(_MANUAL_YAML):
            command = manual_commands.expand(
                entry.command, target=target.ip, port=self._port, basedn=basedn
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
        copy = menu.addAction("Copy command")
        chosen = menu.exec(viewport.mapToGlobal(pos))
        clipboard = QGuiApplication.clipboard()
        if chosen is copy and clipboard is not None:
            clipboard.setText(command)
