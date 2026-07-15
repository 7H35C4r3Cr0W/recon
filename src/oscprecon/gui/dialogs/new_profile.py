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


class NewProfileDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("New Project")
        self._name = QLineEdit()
        self._ip = QLineEdit()
        self._hostname = QLineEdit()
        self._hostname.setPlaceholderText("optional — e.g. thetoppers.htb (add to /etc/hosts)")
        self._box = QComboBox()
        self._box.addItem("(none)")

        form = QFormLayout()
        form.addRow("Profile name:", self._name)
        form.addRow("Target IP:", self._ip)
        form.addRow("Hostname / vhost:", self._hostname)
        form.addRow("Box (optional):", self._box)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def values(self) -> tuple[str, str, str]:
        return (
            self._name.text().strip(),
            self._ip.text().strip(),
            self._hostname.text().strip(),
        )
