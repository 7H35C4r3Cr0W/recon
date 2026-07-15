from __future__ import annotations

from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from oscprecon import ligolo


class LigoloHelperDialog(QDialog):
    """A guided command-builder for the ligolo-ng pivot workflow.

    Nabu never runs ligolo (it's a tunnelling relay, not a recon tool, and a tun/route needs root) —
    this generates the exact copy-paste commands for your values, the same "shown, you run it" model
    as the Tier-2 manual commands. Once the internal /24 is routable over the ligolo interface, use
    Scan → "Scan a host / range" and Nabu scans it transparently. Docs: https://docs.ligolo.ng/
    """

    def __init__(self, default_routes: list[str] | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Pivot with Ligolo-ng")
        self.resize(680, 620)

        intro = QLabel(
            "Reach an internal network from a foothold, then scan it in Nabu. Fill in your values — "
            "the commands below update live. Nabu doesn't run ligolo; copy each command and run it "
            'where it says. <a href="https://docs.ligolo.ng/">docs.ligolo.ng</a>'
        )
        intro.setWordWrap(True)
        intro.setOpenExternalLinks(True)

        self._ip = QLineEdit(ligolo.detect_tun_ip("tun0"))
        self._ip.setPlaceholderText("your VPN/tun0 IP (the agent dials back to this)")
        self._port = QLineEdit("11601")
        self._iface = QLineEdit("ligolo")
        self._routes = QLineEdit()
        self._routes.setPlaceholderText("internal /24(s), comma-separated — e.g. 172.16.1.0/24, 10.10.5.0/24")

        form = QFormLayout()
        form.addRow("Attacker (tun0) IP:", self._ip)
        form.addRow("Proxy port:", self._port)
        form.addRow("Interface name:", self._iface)
        form.addRow("Internal route(s):", self._routes)

        self._steps_host = QWidget()
        self._steps_layout = QVBoxLayout(self._steps_host)
        self._steps_layout.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self._steps_host)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)

        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(form)
        layout.addWidget(QLabel("Steps:"))
        layout.addWidget(scroll, stretch=1)
        layout.addWidget(buttons)

        for widget in (self._ip, self._port, self._iface, self._routes):
            widget.textChanged.connect(self._rebuild)
        if default_routes:
            self._routes.setText(", ".join(default_routes))
        self._rebuild()

    def _rebuild(self) -> None:
        while self._steps_layout.count():
            item = self._steps_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        try:
            port = int(self._port.text().strip() or "11601")
        except ValueError:
            port = 11601
        routes = [r.strip() for r in self._routes.text().replace(";", ",").split(",") if r.strip()]
        steps = ligolo.build_ligolo_steps(
            self._ip.text().strip(), port=port, iface=self._iface.text().strip(), routes=routes
        )
        for step in steps:
            self._steps_layout.addWidget(self._step_card(step))
        self._steps_layout.addStretch(1)

    def _step_card(self, step: ligolo.LigoloStep) -> QWidget:
        card = QFrame()
        card.setFrameShape(QFrame.Shape.StyledPanel)
        outer = QVBoxLayout(card)
        header = QLabel(f"<b>{step.n}. {step.title}</b>  —  <i>on {step.where}</i>")
        header.setWordWrap(True)
        outer.addWidget(header)

        body = QPlainTextEdit("\n".join(step.commands))
        body.setReadOnly(True)
        body.setFont(QFont("monospace"))
        lines = len(step.commands)
        body.setFixedHeight(22 + 18 * max(1, lines))
        row = QHBoxLayout()
        row.addWidget(body, stretch=1)
        copy = QPushButton("Copy")
        copy.clicked.connect(lambda _=False, text="\n".join(step.commands): self._copy(text))
        row.addWidget(copy)
        outer.addLayout(row)

        if step.note:
            note = QLabel(step.note)
            note.setWordWrap(True)
            note.setStyleSheet("color: gray; font-size: 11px;")
            outer.addWidget(note)
        return card

    @staticmethod
    def _copy(text: str) -> None:
        clip = QGuiApplication.clipboard()
        if clip is not None:
            clip.setText(text)
