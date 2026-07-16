from __future__ import annotations

from PySide6.QtCore import QEvent, QEventLoop, Qt
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from oscprecon.gui.theme import styles
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
        self._ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self._ok.setStyleSheet(styles.accent_button())
        self._username.textChanged.connect(self._validate)
        self._secret.textChanged.connect(self._validate)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)
        self._validate()  # Ok stays disabled until the required fields are present

    def _validate(self) -> None:
        self._ok.setEnabled(self._is_valid())

    def _is_valid(self) -> bool:
        return bool(self._username.text().strip()) and bool(self._secret.text())

    def _is_empty(self) -> bool:
        # nothing typed anywhere — a click-away can safely close it (no input to lose)
        fields = (self._username, self._secret, self._domain, self._source, self._notes)
        return not any(w.text().strip() for w in fields)

    def event(self, e: QEvent) -> bool:
        # click outside the dialog (it loses window focus) -> AUTOSAVE & close if the required
        # fields are filled (the "click-away to save" feel the user asked for). Guards:
        #  - ignore deactivation caused by our OWN popup, e.g. opening the Type combo dropdown —
        #    that is not a click-away and must not close the dialog mid-edit [#10];
        #  - NEVER discard typed input on deactivate: if the fields are incomplete, stay open so the
        #    user can Alt-Tab to a password manager to copy the secret and come back [#11]. Only an
        #    untouched (empty) dialog auto-closes on click-away.
        if (
            e.type() == QEvent.Type.WindowDeactivate
            and self.isVisible()
            and QApplication.activePopupWidget() is None
        ):
            if self._is_valid():
                self.accept()
            elif self._is_empty():
                self.reject()
        return super().event(e)

    def exec(self) -> int:
        # run NON-modally so an outside click deactivates + dismisses us, but still block the caller
        # (its `dialog.exec() == Accepted` flow) via a local event loop until we close.
        self.setWindowModality(Qt.WindowModality.NonModal)
        self.show()
        self.raise_()
        self.activateWindow()
        loop = QEventLoop()
        self.finished.connect(loop.quit)
        loop.exec()
        return self.result()

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
