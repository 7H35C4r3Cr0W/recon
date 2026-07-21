from __future__ import annotations

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
from oscprecon.gui.simple_recon import SimpleReconSpec
from oscprecon.gui.theme import styles
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
        self._host_ip = ""  # a pivoted host's IP; "" = the entry target
        self._port = 0

        self._recon = QPushButton(spec.label)
        self._recon.setStyleSheet(styles.accent_button())  # flagship Tier-1 action
        self._recon.clicked.connect(lambda: self.recon_requested.emit(spec.module, self._port))
        button_box = QGroupBox(
            "Tier 1 — read-only recon (streams to the output pane + findings.json)"
        )
        QVBoxLayout(button_box).addWidget(self._recon)

        self._manual = QListWidget()
        self._manual.itemActivated.connect(self._on_manual_activated)
        self._manual.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._manual.customContextMenuRequested.connect(self._on_manual_menu)
        manual_box = QGroupBox(
            "Manual follow-ups (Tier 2 — double-click to run · right-click → Copy to edit "
            "literals first)"
        )
        QVBoxLayout(manual_box).addWidget(self._manual)

        self._summary = QListWidget()
        self._seed_summary_placeholder()
        summary_box = QGroupBox("Findings so far")
        QVBoxLayout(summary_box).addWidget(self._summary)

        intro = QLabel(spec.intro)
        intro.setWordWrap(True)  # long intros must not force a wide minimum on the whole tool panel
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
        self._host_ip = host_ip
        self._port = service.port
        self._reload_manual()

    def set_running(self, running: bool) -> None:
        self._recon.setEnabled(not running)

    def set_summary(self, lines: list[str]) -> None:
        self._summary.clear()
        if not lines:
            self._seed_summary_placeholder()
            return
        for line in lines:
            self._summary.addItem(line)

    def _seed_summary_placeholder(self) -> None:
        item = QListWidgetItem("Run the recon button above to populate findings.")
        item.setFlags(Qt.ItemFlag.NoItemFlags)
        self._summary.addItem(item)

    def _reload_manual(self) -> None:
        self._manual.clear()
        if self._profile is None:
            return
        target = self._profile.target
        # pre-fill {user}/{password}/{domain} from the first password credential (mirrors smb_panel)
        # so credentialed follow-ups (kerberos/mssql/winrm/…) come filled instead of collapsing the
        # placeholders to empty strings and looking runnable-but-broken.
        cred = next((c for c in self._profile.credentials() if c.secret_type == "password"), None)
        user = cred.username if cred is not None else ""
        password = cred.secret if cred is not None else ""
        domain = (cred.domain if cred is not None and cred.domain else "") or target.hostname or ""
        for entry in manual_commands.load_manual_commands(self._spec.manual_yaml):
            command = manual_commands.expand(
                entry.command,
                target=(self._host_ip or target.ip),
                port=self._port,
                domain=domain,
                user=user,
                password=password,
            )
            item = QListWidgetItem(f"{entry.description}\n    {command}")
            item.setData(_COMMAND_ROLE, command)
            # dim entries that need creds we don't have yet — running them just fails on empty auth.
            if "creds" in entry.requires and cred is None:
                item.setFlags(Qt.ItemFlag.NoItemFlags)
                item.setToolTip("Add a credential first (this command needs {user}/{password}).")
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
