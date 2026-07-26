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
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from oscprecon import manual_commands
from oscprecon.gui.theme import styles
from oscprecon.gui.widgets.auth_picker import AuthPicker
from oscprecon.models import DiscoveredService
from oscprecon.modules import smb as smb_mod
from oscprecon.profile import Profile
from oscprecon.recon_auth import ReconAuth, prefill_identity

_MANUAL_YAML = Path(smb_mod.__file__).parent / "manual_commands.yaml"
_COMMAND_ROLE = Qt.ItemDataRole.UserRole


class SmbPanel(QWidget):
    recon_requested = Signal(str, object)  # (mode: full | null | guest | shares, ReconAuth | None)
    manual_requested = Signal(str)  # command

    def __init__(self) -> None:
        super().__init__()
        self._profile: Profile | None = None
        self._host_ip = ""  # a pivoted host's IP; "" = the entry target

        # "Run as" — anonymous by default, or any vault credential. Guest is offered here too so
        # the identity lives in ONE control instead of being split between a dropdown and a button.
        self._auth = AuthPicker((("guest (empty password)", ReconAuth.guest()),))
        self._auth.changed.connect(self._on_identity_changed)

        self._full = QPushButton("Run full SMB recon")
        self._full.setStyleSheet(styles.accent_button())  # flagship Tier-1 action
        self._full.clicked.connect(lambda: self._emit_recon("full"))
        self._null = QPushButton("Just check null session")
        self._null.clicked.connect(lambda: self.recon_requested.emit("null", None))
        self._guest = QPushButton("Just check guest")
        self._guest.clicked.connect(lambda: self.recon_requested.emit("guest", ReconAuth.guest()))
        self._shares = QPushButton("Just enumerate shares")
        self._shares.clicked.connect(lambda: self._emit_recon("shares"))
        button_box = QGroupBox("Tier 1 — automatic recon")
        button_layout = QVBoxLayout(button_box)
        button_layout.addWidget(self._auth)
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

        # why: the four Run buttons are fixed-size, but the follow-up list and the findings list
        # both grow without bound — 20 shares and 40 users crushed them into two slivers. The
        # buttons keep their natural height; the two lists share a DRAGGABLE split so whichever one
        # you are reading can take the space.
        self._split = QSplitter(Qt.Orientation.Vertical)
        self._split.setChildrenCollapsible(True)
        self._split.addWidget(manual_box)
        self._split.addWidget(summary_box)
        self._split.setStretchFactor(0, 1)
        self._split.setStretchFactor(1, 2)
        self._split.setSizes([170, 320])
        self._manual.setMinimumHeight(70)
        self._summary.setMinimumHeight(90)

        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addWidget(button_box)
        layout.addWidget(self._split, stretch=1)

    def set_profile(self, profile: Profile) -> None:
        self._profile = profile
        self._auth.set_credentials(list(profile.credentials()))
        self._reload_manual()
        self._relabel_buttons()

    def refresh_credentials(self) -> None:
        if self._profile is not None:
            self._auth.set_credentials(list(self._profile.credentials()))

    def selected_auth(self) -> ReconAuth | None:
        return self._auth.current_auth()

    def _emit_recon(self, mode: str) -> None:
        self.recon_requested.emit(mode, self._auth.current_auth())

    def _on_identity_changed(self) -> None:
        self._relabel_buttons()
        self._reload_manual()  # the Tier-2 follow-ups fill from the SAME identity

    def _relabel_buttons(self) -> None:
        # the button has to say who it will run as — otherwise picking a credential and pressing
        # "Run full SMB recon" looks identical to the anonymous run that came before it.
        auth = self._auth.current_auth()
        who = "" if auth is None else f" as {auth.username}"
        self._full.setText(f"Run full SMB recon{who}")
        self._shares.setText(f"Just enumerate shares{who}")

    def configure(self, service: DiscoveredService, host_ip: str = "") -> None:
        self._host_ip = host_ip
        self.refresh_credentials()
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
        # pre-fill {user}/{password}/{domain} from the PICKED identity (else the first collected
        # password credential) so the netexec/CME follow-ups come ready to run as the same account
        # the Tier-1 buttons above them use (the user still reviews before running).
        creds = list(self._profile.credentials())
        user, password, domain = prefill_identity(
            self._auth.current_auth(), creds, target.hostname or ""
        )
        for entry in manual_commands.load_manual_commands(_MANUAL_YAML):
            command = manual_commands.expand(
                entry.command,
                target=(self._host_ip or target.ip),
                domain=domain,
                user=user,
                password=password,
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
