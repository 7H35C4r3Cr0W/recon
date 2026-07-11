from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
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
from oscprecon.models import DiscoveredService, validate_host
from oscprecon.modules import dns as dns_mod
from oscprecon.profile import Profile

_MANUAL_YAML = Path(dns_mod.__file__).parent / "manual_commands.yaml"
_COMMAND_ROLE = Qt.ItemDataRole.UserRole


class DnsPanel(QWidget):
    recon_requested = Signal(str, int)  # (domain, port)
    manual_requested = Signal(str)  # command
    validation_failed = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self._profile: Profile | None = None
        self._port = 53

        self._domain = QLineEdit()
        self._domain.setPlaceholderText("zone / domain (e.g. example.htb) — needed for AXFR")
        self._domain.textChanged.connect(self._reload_manual)
        form = QFormLayout()
        form.addRow("Domain:", self._domain)

        self._recon = QPushButton("Run full DNS recon (version, recursion, zone transfer)")
        self._recon.clicked.connect(self._on_recon)
        button_box = QGroupBox("Tier 1 — DNS-protocol recon (read-only queries)")
        box_layout = QVBoxLayout(button_box)
        box_layout.addLayout(form)
        box_layout.addWidget(self._recon)

        self._manual = QListWidget()
        self._manual.itemActivated.connect(self._on_manual_activated)
        self._manual.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._manual.customContextMenuRequested.connect(self._on_manual_menu)
        manual_box = QGroupBox("Manual follow-ups (Tier 2 — double-click; edit TARGET_IP)")
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
            QLabel("DNS recon — protocol queries only; subdomain brute-forcing lives in Vhosts.")
        )
        layout.addLayout(top, stretch=1)

    def set_profile(self, profile: Profile) -> None:
        self._profile = profile
        # why: only seed the domain when empty so a scan-end refresh can't clobber a user edit.
        if profile.target.hostname and not self._domain.text().strip():
            self._domain.setText(profile.target.hostname)
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
        domain = self._domain.text().strip()
        if domain:
            try:
                validate_host(domain)
            except ValueError:
                self.validation_failed.emit(f"invalid domain: {domain!r}")
                return
        self.recon_requested.emit(domain, self._port)

    def _reload_manual(self) -> None:
        self._manual.clear()
        if self._profile is None:
            return
        target = self._profile.target
        # why: the manual path interpolates {domain} into a runnable dig/dnsrecon command, so an
        # unvalidated field could smuggle argv tokens (e.g. a subdomain-brute flag). Normalize it
        # through the same validate_host gate the recon button uses; blank it if it doesn't pass.
        domain = dns_mod.normalize_domain(self._domain.text()) or ""
        for entry in manual_commands.load_manual_commands(_MANUAL_YAML):
            command = manual_commands.expand(
                entry.command, target=target.ip, port=self._port, domain=domain
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
