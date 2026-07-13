from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from oscprecon import creds as creds_mod
from oscprecon.gui.dialogs.credential import AddCredentialDialog
from oscprecon.models import Credential
from oscprecon.profile import Profile

_CRED_ROLE = int(Qt.ItemDataRole.UserRole)
_COLUMNS = ("Username", "Domain", "Type", "Secret", "Source", "Confirmed")


def _confirmed_label(cred: Credential) -> str:
    # which services a spray confirmed this credential against (from tested_against, add-only)
    services = [t.split(":", 1)[1] for t in cred.tested_against if t.startswith("spray-confirmed:")]
    return ", ".join(services) if services else "—"


class CredentialVaultDialog(QDialog):
    """Editable credential vault (add / edit / delete) — the store the spray workflow (§2a) uses.

    Secrets are ALWAYS masked in the table (length only); the plaintext is only ever placed on the
    clipboard via the explicit "Copy secret" action, never shown.
    """

    secret_copied = Signal(str)  # emits the USERNAME only (never the secret) for the audit trail

    def __init__(self, profile: Profile, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._profile = profile
        self._read_only = profile.read_only
        self.setWindowTitle(f"Credential Vault — {profile.profile_name}")
        self.resize(680, 420)

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        self._add = QPushButton("Add…")
        self._add.clicked.connect(self._on_add)
        self._edit = QPushButton("Edit…")
        self._edit.clicked.connect(self._on_edit)
        self._delete = QPushButton("Delete")
        self._delete.clicked.connect(self._on_delete)
        self._copy_user = QPushButton("Copy username")
        self._copy_user.clicked.connect(self._on_copy_username)
        self._copy_secret = QPushButton("Copy secret")
        self._copy_secret.clicked.connect(self._on_copy_secret)

        row = QHBoxLayout()
        for widget in (self._add, self._edit, self._delete):
            row.addWidget(widget)
        row.addStretch(1)
        row.addWidget(self._copy_user)
        row.addWidget(self._copy_secret)

        note = QLabel(
            "Secrets are masked (length only) and only leave via <b>Copy secret</b>. Credentials "
            "are durable project data — they persist until you edit or delete them here."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color: gray;")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self._table, stretch=1)
        layout.addLayout(row)
        layout.addWidget(note)
        layout.addWidget(buttons)

        if self._read_only:  # copy stays available; mutation does not
            for widget in (self._add, self._edit, self._delete):
                widget.setEnabled(False)
        self._refresh()

    def _refresh(self) -> None:
        self._table.setRowCount(0)
        for cred in self._profile.credentials():
            r = self._table.rowCount()
            self._table.insertRow(r)
            cells = (
                cred.username,
                cred.domain or "—",
                cred.secret_type,
                creds_mod.redact(cred.secret),
                cred.source or "manual",
                _confirmed_label(cred),
            )
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col == 0:
                    item.setData(_CRED_ROLE, cred)
                self._table.setItem(r, col, item)

    def _selected_cred(self) -> Credential | None:
        rows = self._table.selectionModel().selectedRows() if self._table.selectionModel() else []
        if not rows:
            return None
        item = self._table.item(rows[0].row(), 0)
        cred = item.data(_CRED_ROLE) if item is not None else None
        return cred if isinstance(cred, Credential) else None

    def _on_add(self) -> None:
        dialog = AddCredentialDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        cred = dialog.credential()
        if cred is not None and not self._read_only:
            self._profile.add_credential(cred)
            self._refresh()

    def _on_edit(self) -> None:
        current = self._selected_cred()
        if current is None or self._read_only:
            return
        dialog = AddCredentialDialog(self, credential=current)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        updated = dialog.credential()
        if updated is not None:
            self._profile.delete_credential(current)  # edit = delete then re-add
            self._profile.add_credential(updated)
            self._refresh()

    def _on_delete(self) -> None:
        current = self._selected_cred()
        if current is not None and not self._read_only:
            self._profile.delete_credential(current)
            self._refresh()

    def _on_copy_username(self) -> None:
        cred = self._selected_cred()
        if cred is not None:
            QGuiApplication.clipboard().setText(cred.username)

    def _on_copy_secret(self) -> None:
        # explicit user action — the plaintext goes to the clipboard only, never to the UI/logs
        cred = self._selected_cred()
        if cred is not None:
            QGuiApplication.clipboard().setText(cred.secret)
            # username only — the audit line this drives must carry no secret
            self.secret_copied.emit(cred.username)
