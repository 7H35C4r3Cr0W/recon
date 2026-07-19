from __future__ import annotations

from PySide6.QtCore import QEvent, QEventLoop, Qt, QTimer, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from oscprecon import creds as creds_mod
from oscprecon.gui.dialogs.credential import AddCredentialDialog
from oscprecon.gui.theme import styles, tokens
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
        self._add.setStyleSheet(styles.accent_button())  # primary action
        self._add.clicked.connect(self._on_add)
        self._edit = QPushButton("Edit…")
        self._edit.clicked.connect(self._on_edit)
        self._delete = QPushButton("Delete")
        self._delete.setStyleSheet(styles.danger_button(tokens.DARK))  # destructive
        self._delete.clicked.connect(self._on_delete)
        self._copy_user = QPushButton("Copy username")
        self._copy_user.clicked.connect(self._on_copy_username)
        self._copy_secret = QPushButton("Copy secret")
        self._copy_secret.clicked.connect(self._on_copy_secret)
        self._table.itemSelectionChanged.connect(self._update_actions)

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
        note.setStyleSheet(f"color: {tokens.active_palette().text_muted};")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self._table, stretch=1)
        layout.addLayout(row)
        layout.addWidget(note)
        layout.addWidget(buttons)

        if self._read_only:  # add stays off entirely; row actions are gated by selection below
            self._add.setEnabled(False)
        self._refresh()
        self._update_actions()

    def exec(self) -> int:
        # run NON-modally so a click outside dismisses the vault (click-away-to-close), while still
        # blocking the caller via a local loop until it closes. The vault holds no unsaved input
        # (adds/edits persist through their own dialog), so a click-away loses nothing.
        self.setWindowModality(Qt.WindowModality.NonModal)
        self.show()
        self.raise_()
        self.activateWindow()
        loop = QEventLoop()
        self.finished.connect(loop.quit)
        loop.exec()
        return self.result()

    def event(self, e: QEvent) -> bool:
        # defer the decision one tick so QApplication.activeWindow() has settled onto whatever the
        # user clicked (or onto a child dialog we just opened).
        if e.type() == QEvent.Type.WindowDeactivate and self.isVisible():
            QTimer.singleShot(0, self._maybe_close_on_click_away)
        return super().event(e)

    def _maybe_close_on_click_away(self) -> None:
        if not self.isVisible():
            return
        # a combo popup, or a child dialog we spawned (Add/Edit/delete-confirm — all parented to us)
        # is NOT a click-away; only a click onto an unrelated window dismisses the vault.
        if QApplication.activePopupWidget() is not None:
            return
        w = QApplication.activeWindow()
        while w is not None:
            if w is self:
                return  # focus is on us or a dialog we own
            w = w.parentWidget()
        self.reject()

    def _update_actions(self) -> None:
        # row actions need a selected credential; mutation also needs a writable profile
        has = self._selected_cred() is not None
        self._edit.setEnabled(has and not self._read_only)
        self._delete.setEnabled(has and not self._read_only)
        self._copy_user.setEnabled(has)
        self._copy_secret.setEnabled(has)

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
        self._update_actions()

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
        if updated is None:
            return
        # single atomic write instead of delete-then-add (avoids losing the cred on a failed write
        # [#12] and the silent-drop-on-collision bug [#37]) — see Profile.replace_credential.
        self._profile.replace_credential(current, updated)
        self._refresh()

    def _on_delete(self) -> None:
        current = self._selected_cred()
        if current is None or self._read_only:
            return
        # credentials are durable project data — a destructive removal is confirmed explicitly
        confirm = QMessageBox.question(
            self,
            "Delete credential",
            f"Delete the stored credential for “{current.username}”? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm == QMessageBox.StandardButton.Yes:
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
