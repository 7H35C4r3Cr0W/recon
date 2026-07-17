from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
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

        # ── Credentials to spray (pick the subset; all selected by default) ──
        creds_box = QGroupBox("Credentials to spray — all selected by default; untick to narrow")
        creds_outer = QVBoxLayout(creds_box)
        columns = QHBoxLayout()
        self._users_list = QListWidget()
        self._users_list.setAccessibleName("Usernames to spray")
        self._pass_list = QListWidget()
        self._pass_list.setAccessibleName("Passwords to spray")
        for title, widget in (("Usernames", self._users_list), ("Passwords", self._pass_list)):
            column = QVBoxLayout()
            column.addWidget(QLabel(title))
            column.addWidget(widget)
            columns.addLayout(column)
        self._users_list.itemChanged.connect(self._refresh_preview)
        self._pass_list.itemChanged.connect(self._refresh_preview)
        creds_outer.addLayout(columns)
        manage = QPushButton("Manage vault…")
        manage.clicked.connect(self._on_manage_vault)
        creds_outer.addWidget(manage, alignment=Qt.AlignmentFlag.AlignRight)
        layout.addWidget(creds_box, stretch=1)

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

        self._populate_creds()
        self._refresh_preview()

    def selected_services(self) -> list[str]:
        return [key for key, box in self._checks.items() if box.isChecked()]

    def selected_users(self) -> list[str]:
        return _checked_texts(self._users_list)

    def selected_passwords(self) -> list[str]:
        return [
            str(self._pass_list.item(i).data(Qt.ItemDataRole.UserRole))
            for i in range(self._pass_list.count())
            if self._pass_list.item(i).checkState() == Qt.CheckState.Checked
        ]

    def _populate_creds(self) -> None:
        users, passwords = spray.vault_material(self._profile.credentials())
        self._users_list.clear()
        self._pass_list.clear()
        for username in users:
            self._users_list.addItem(_checkable_item(username))
        for password in passwords:
            # mask the secret on screen (distinguishable by length); the value rides in UserRole
            item = _checkable_item(f"•••••• ({len(password)} chars)")
            item.setData(Qt.ItemDataRole.UserRole, password)
            self._pass_list.addItem(item)

    def _on_manage_vault(self) -> None:
        CredentialVaultDialog(self._profile, self).exec()
        self._populate_creds()
        self._refresh_preview()

    def _refresh_preview(self) -> None:
        users_path = self._profile.directory / "spray" / "users.txt"
        passwords_path = self._profile.directory / "spray" / "passwords.txt"
        services = self._profile.discovered_services
        commands = [
            spray.build_spray_command(
                key,
                self._profile.target.ip,
                users_path,
                passwords_path,
                spray.discovered_port(key, services),
            )
            for key in self.selected_services()
        ]
        header = (
            f"# {len(self.selected_users())} username(s) × "
            f"{len(self.selected_passwords())} password(s) selected\n"
        )
        body = "\n".join(commands) or "(select one or more services)"
        self._preview.setPlainText(header + body)

    def _on_run(self) -> None:
        if self._enabled and self.selected_services():
            self.accept()


def _checkable_item(text: str) -> QListWidgetItem:
    item = QListWidgetItem(text)
    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
    item.setCheckState(Qt.CheckState.Checked)
    return item


def _checked_texts(lst: QListWidget) -> list[str]:
    return [
        lst.item(i).text()
        for i in range(lst.count())
        if lst.item(i).checkState() == Qt.CheckState.Checked
    ]
