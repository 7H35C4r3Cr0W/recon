from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from oscprecon import creds as creds_mod
from oscprecon.gui.dialogs.credential import AddCredentialDialog
from oscprecon.models import Credential
from oscprecon.profile import Profile

_CRED_ROLE = int(Qt.ItemDataRole.UserRole)


class CredentialVaultDialog(QDialog):
    """Editable credential vault (add / delete) — the creds the spray workflow (§2a) draws from."""

    def __init__(self, profile: Profile, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._profile = profile
        self.setWindowTitle(f"Credential Vault — {profile.profile_name}")
        self.resize(560, 380)

        self._list = QListWidget()
        add = QPushButton("Add…")
        add.clicked.connect(self._on_add)
        self._delete = QPushButton("Delete")
        self._delete.clicked.connect(self._on_delete)
        row = QHBoxLayout()
        row.addWidget(add)
        row.addWidget(self._delete)
        row.addStretch(1)

        note = QLabel(
            "Secrets are shown redacted (length only). This is the vault credential spraying draws "
            "from — add/delete freely; edit = delete then re-add."
        )
        note.setWordWrap(True)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)

        layout = QVBoxLayout(self)
        layout.addWidget(self._list, stretch=1)
        layout.addLayout(row)
        layout.addWidget(note)
        layout.addWidget(buttons)

        self._read_only = profile.read_only
        if self._read_only:
            add.setEnabled(False)
            self._delete.setEnabled(False)
        self._refresh()

    def _refresh(self) -> None:
        self._list.clear()
        for cred in self._profile.credentials():
            at = f"@{cred.domain}" if cred.domain else ""
            label = (
                f"{cred.username}{at}  ·  {cred.secret_type}: {creds_mod.redact(cred.secret)}"
                f"  ·  {cred.source or 'manual'}"
            )
            item = QListWidgetItem(label)
            item.setData(_CRED_ROLE, cred)
            self._list.addItem(item)

    def _on_add(self) -> None:
        dialog = AddCredentialDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        cred = dialog.credential()
        if cred is not None and not self._read_only:
            self._profile.add_credential(cred)
            self._refresh()

    def _on_delete(self) -> None:
        if self._read_only:
            return
        for item in self._list.selectedItems():
            cred = item.data(_CRED_ROLE)
            if isinstance(cred, Credential):
                self._profile.delete_credential(cred)
        self._refresh()
