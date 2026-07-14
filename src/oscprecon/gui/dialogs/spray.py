from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from oscprecon import spray
from oscprecon.gui.dialogs.cred_vault import CredentialVaultDialog
from oscprecon.gui.theme import styles, tokens
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
            banner.setStyleSheet(f"color: {tokens.DARK.error}; font-weight: bold;")
            layout.addWidget(banner)

        # ── Credentials ──────────────────────────────────────────────
        creds_box = QGroupBox("Credentials")
        creds_layout = QHBoxLayout(creds_box)
        self._vault_label = QLabel()
        manage = QPushButton("Manage vault…")
        manage.clicked.connect(self._on_manage_vault)
        creds_layout.addWidget(self._vault_label, stretch=1)
        creds_layout.addWidget(manage)
        layout.addWidget(creds_box)

        # ── Services ─────────────────────────────────────────────────
        services_box = QGroupBox("Services to spray")
        services_layout = QVBoxLayout(services_box)
        self._checks: dict[str, QCheckBox] = {}
        for service in spray.SPRAY_SERVICES:
            box = QCheckBox(service.label)
            box.toggled.connect(self._refresh_preview)
            self._checks[service.key] = box
            services_layout.addWidget(box)
        layout.addWidget(services_box)

        # ── Command preview ──────────────────────────────────────────
        preview_box = QGroupBox("Command preview (vault users × passwords, discovered ports)")
        preview_layout = QVBoxLayout(preview_box)
        self._preview = QPlainTextEdit()
        self._preview.setReadOnly(True)
        preview_layout.addWidget(self._preview)
        layout.addWidget(preview_box, stretch=1)

        button_row = QHBoxLayout()
        self._run = QPushButton("Run selected sprays")
        self._run.setStyleSheet(styles.accent_button())  # primary (gated) action
        self._run.setEnabled(spray_enabled)
        self._run.clicked.connect(self._on_run)
        close = QPushButton("Close")
        close.clicked.connect(self.reject)
        button_row.addStretch(1)
        button_row.addWidget(close)
        button_row.addWidget(self._run)  # primary sits right-most (consistent dialog ordering)
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
        services = self._profile.discovered_services
        commands = [
            spray.build_spray_command(
                key,
                self._profile.target.ip,
                users,
                passwords,
                spray.discovered_port(key, services),
            )
            for key in self.selected_services()
        ]
        self._preview.setPlainText("\n".join(commands) or "(select one or more services)")

    def _on_run(self) -> None:
        if self._enabled and self.selected_services():
            self.accept()
