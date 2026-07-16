from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)


class NewProfileDialog(QDialog):
    """Create OR edit a project. The target may be a single host/hostname or a whole CIDR range
    (a /24 network project). In edit mode fields are pre-filled and the box dropdown is hidden."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        title: str = "New Project",
        name: str = "",
        ip: str = "",
        hostname: str = "",
        edit: bool = False,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self._name = QLineEdit(name)
        self._ip = QLineEdit(ip)
        self._ip.setPlaceholderText("10.10.10.5   ·   a whole /24:  10.10.5.0/24")
        self._hostname = QLineEdit(hostname)
        self._hostname.setPlaceholderText("optional — e.g. thetoppers.htb (add to /etc/hosts)")
        self._box = QComboBox()
        self._box.addItem("(none)")

        form = QFormLayout()
        form.addRow("Project name:", self._name)
        form.addRow("Target IP or range:", self._ip)
        form.addRow("Hostname / vhost:", self._hostname)
        if not edit:
            form.addRow("Box (optional):", self._box)

        hint = QLabel(
            "A range like <code>10.10.5.0/24</code> makes a whole-network project — Run Recon then "
            "discovers live hosts across it into the topology (a /24 network has no vhost name)."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: palette(mid);")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        if edit:
            buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Save changes")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(hint)
        layout.addWidget(buttons)

    def values(self) -> tuple[str, str, str]:
        return (
            self._name.text().strip(),
            self._ip.text().strip(),
            self._hostname.text().strip(),
        )
