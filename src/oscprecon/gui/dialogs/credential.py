from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from oscprecon.models import Credential


class AddCredentialDialog(QDialog):
    def __init__(self, parent: QWidget | None = None, credential: Credential | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit Credential" if credential is not None else "Add Credential")
        self._username = QLineEdit()
        self._secret = QLineEdit()
        self._secret.setEchoMode(QLineEdit.EchoMode.Password)
        self._secret_type = QComboBox()
        self._secret_type.addItems(["password", "hash", "key"])
        self._domain = QLineEdit()
        self._source = QLineEdit()
        self._notes = QLineEdit()
        if credential is not None:  # prefill for edit
            self._username.setText(credential.username)
            self._secret.setText(credential.secret)
            idx = self._secret_type.findText(credential.secret_type)
            self._secret_type.setCurrentIndex(idx if idx >= 0 else 0)
            self._domain.setText(credential.domain)
            self._source.setText(credential.source)
            self._notes.setText(credential.notes)

        form = QFormLayout()
        form.addRow("Username:", self._username)
        form.addRow("Secret:", self._secret)
        form.addRow("Type:", self._secret_type)
        form.addRow("Domain:", self._domain)
        form.addRow("Source:", self._source)
        form.addRow("Notes:", self._notes)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def credential(self) -> Credential | None:
        username = self._username.text().strip()
        secret = self._secret.text()
        if not username or not secret:
            return None
        return Credential(
            username=username,
            secret=secret,
            secret_type=self._secret_type.currentText(),
            domain=self._domain.text().strip(),
            source=self._source.text().strip() or "manual",
            notes=self._notes.text().strip(),
        )
