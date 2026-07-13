from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from oscprecon import spray
from oscprecon.gui.dialogs.cred_vault import CredentialVaultDialog
from oscprecon.profile import Profile


class SprayDialog(QDialog):
    """Opt-in credential spraying (§2a) — pick services + preview; Run is gated on Spray mode.

    Builds nothing runnable itself: on accept the caller reads selected_services(), writes the spray
    lists, and launches each command through shell.run(spray=True) — which is itself gated on the
    spray_enabled setting. This dialog only runs when the caller passes spray_enabled=True.
    """

    def __init__(
        self, profile: Profile, spray_enabled: bool, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._profile = profile
        self._enabled = spray_enabled
        self.setWindowTitle(f"Credential Spray — {profile.profile_name}")
        self.resize(620, 460)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"<b>Target:</b> {profile.target.ip} (single target only)"))

        if not spray_enabled:
            banner = QLabel(
                "⚠ Spray mode is OFF. Enable it in Preferences → Scan to run. "
                "OSCP-legal against your own authorized targets only (§ 2a)."
            )
            banner.setWordWrap(True)
            banner.setStyleSheet("color: #c0392b; font-weight: bold;")
            layout.addWidget(banner)

        vault_row = QHBoxLayout()
        self._vault_label = QLabel()
        manage = QPushButton("Manage vault…")
        manage.clicked.connect(self._on_manage_vault)
        vault_row.addWidget(self._vault_label, stretch=1)
        vault_row.addWidget(manage)
        layout.addLayout(vault_row)

        layout.addWidget(QLabel("Services to spray:"))
        self._checks: dict[str, QCheckBox] = {}
        for service in spray.SPRAY_SERVICES:
            box = QCheckBox(service.label)
            box.toggled.connect(self._refresh_preview)
            self._checks[service.key] = box
            layout.addWidget(box)

        layout.addWidget(QLabel("Preview (runs against the vault's users × passwords):"))
        self._preview = QPlainTextEdit()
        self._preview.setReadOnly(True)
        layout.addWidget(self._preview, stretch=1)

        button_row = QHBoxLayout()
        self._run = QPushButton("Run selected sprays")
        self._run.setEnabled(spray_enabled)
        self._run.clicked.connect(self._on_run)
        close = QPushButton("Close")
        close.clicked.connect(self.reject)
        button_row.addStretch(1)
        button_row.addWidget(self._run)
        button_row.addWidget(close)
        layout.addLayout(button_row)

        self._refresh_vault_summary()
        self._refresh_preview()

    def selected_services(self) -> list[str]:
        return [key for key, box in self._checks.items() if box.isChecked()]

    def _refresh_vault_summary(self) -> None:
        users, passwords = spray.vault_material(self._profile.credentials())
        self._vault_label.setText(f"Vault: {len(users)} username(s) × {len(passwords)} password(s)")

    def _on_manage_vault(self) -> None:
        CredentialVaultDialog(self._profile, self).exec()
        self._refresh_vault_summary()
        self._refresh_preview()

    def _refresh_preview(self) -> None:
        users = self._profile.directory / "spray" / "users.txt"
        passwords = self._profile.directory / "spray" / "passwords.txt"
        commands = [
            spray.build_spray_command(key, self._profile.target.ip, users, passwords)
            for key in self.selected_services()
        ]
        self._preview.setPlainText("\n".join(commands) or "(select one or more services)")

    def _on_run(self) -> None:
        if self._enabled and self.selected_services():
            self.accept()
