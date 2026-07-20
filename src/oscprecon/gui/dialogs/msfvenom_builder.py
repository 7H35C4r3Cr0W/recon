from __future__ import annotations

from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from oscprecon.exploit import msfvenom
from oscprecon.gui.theme import styles
from oscprecon.ligolo import detect_tun_ip

# Optional encoders offered in the dropdown (empty = none). Bad-char evasion / AV is a common OSCP
# pain point, so the two most-used encoders are one click away.
_ENCODERS = [
    "",
    "x86/shikata_ga_nai",
    "x64/xor_dynamic",
    "x86/call4_dword_xor",
    "cmd/powershell_base64",
]


class MsfvenomBuilderDialog(QDialog):
    """A guided msfvenom payload builder — pick platform/payload/format, fill LHOST/LPORT, and copy
    the exact command plus its matching listener. Nabu does NOT run msfvenom; this is a copy-only
    syntax helper (the operator runs it). msfvenom + multi/handler are OSCP-legal; a plain
    *_reverse_tcp shell caught with netcat has no exam limit (meterpreter is flagged when chosen).
    """

    def __init__(self, lhost: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("msfvenom payload builder")
        self.resize(720, 620)

        intro = QLabel(
            "Build a reverse-shell payload without wrestling the syntax. Pick the target, fill "
            "your LHOST/LPORT — the command and its listener update live. Copy and run them "
            "yourself; Nabu doesn't execute msfvenom."
        )
        intro.setWordWrap(True)

        self._platform = QComboBox()
        for plat in msfvenom.PLATFORMS:
            self._platform.addItem(plat.label, plat.key)
        self._payload = QComboBox()
        self._fmt = QComboBox()
        self._fmt.setEditable(False)
        for fmt in msfvenom.FORMATS:
            self._fmt.addItem(fmt, fmt)

        self._lhost = QLineEdit(lhost or detect_tun_ip("tun0") or detect_tun_ip("tun1"))
        self._lhost.setPlaceholderText("your VPN/tun0 IP")
        self._lport = QSpinBox()
        self._lport.setRange(1, 65535)
        self._lport.setValue(4444)
        self._encoder = QComboBox()
        for enc in _ENCODERS:
            self._encoder.addItem(enc or "(none)", enc)
        self._iterations = QSpinBox()
        self._iterations.setRange(1, 50)
        self._iterations.setValue(1)
        self._badchars = QLineEdit()
        self._badchars.setPlaceholderText(r"optional, e.g. \x00\x0a\x0d")
        self._outfile = QLineEdit()
        self._outfile.setPlaceholderText("output file (auto from format)")

        form = QFormLayout()
        form.addRow("Target platform:", self._platform)
        form.addRow("Payload:", self._payload)
        form.addRow("Format:", self._fmt)
        form.addRow("LHOST:", self._lhost)
        form.addRow("LPORT:", self._lport)
        form.addRow("Encoder:", self._encoder)
        form.addRow("Encoder iterations:", self._iterations)
        form.addRow("Bad chars:", self._badchars)
        form.addRow("Output file:", self._outfile)

        self._command = QPlainTextEdit()
        self._command.setReadOnly(True)
        self._command.setFont(QFont("monospace"))
        self._command.setFixedHeight(56)
        copy_cmd = QPushButton("Copy command")
        copy_cmd.setStyleSheet(styles.accent_button())
        copy_cmd.clicked.connect(lambda: self._copy(self._command.toPlainText(), copy_cmd))
        cmd_row = QHBoxLayout()
        cmd_row.addWidget(self._command, stretch=1)
        cmd_row.addWidget(copy_cmd)

        self._listener = QPlainTextEdit()
        self._listener.setReadOnly(True)
        self._listener.setFont(QFont("monospace"))
        self._listener.setFixedHeight(56)
        copy_listen = QPushButton("Copy listener")
        copy_listen.clicked.connect(lambda: self._copy(self._listener.toPlainText(), copy_listen))
        listen_row = QHBoxLayout()
        listen_row.addWidget(self._listener, stretch=1)
        listen_row.addWidget(copy_listen)

        self._notes = QLabel("")
        self._notes.setWordWrap(True)
        self._notes.setStyleSheet("color: #d08770; font-size: 11px;")  # on-brand caution amber

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)

        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(form)
        layout.addWidget(QLabel("<b>Generate the payload (on Kali):</b>"))
        layout.addLayout(cmd_row)
        layout.addWidget(QLabel("<b>Catch the shell (start this first):</b>"))
        layout.addLayout(listen_row)
        layout.addWidget(self._notes)
        layout.addWidget(buttons)

        self._platform.currentIndexChanged.connect(self._reload_payloads)
        self._payload.currentIndexChanged.connect(self._on_payload_changed)
        for w in (self._fmt, self._encoder):
            w.currentIndexChanged.connect(self._rebuild)
        self._lhost.textChanged.connect(self._rebuild)
        self._badchars.textChanged.connect(self._rebuild)
        self._outfile.textChanged.connect(self._rebuild)
        self._lport.valueChanged.connect(self._rebuild)
        self._iterations.valueChanged.connect(self._rebuild)

        self._reload_payloads()

    def _reload_payloads(self) -> None:
        key = self._platform.currentData()
        plat = msfvenom.platform(key)
        self._payload.blockSignals(True)
        self._payload.clear()
        if plat is not None:
            for p in plat.payloads:
                self._payload.addItem(p.label, p.id)
        self._payload.blockSignals(False)
        self._on_payload_changed()

    def _on_payload_changed(self) -> None:
        # sync the format dropdown + suggested output filename to the chosen payload's defaults
        pid = self._payload.currentData()
        payload = msfvenom.find_payload(pid) if pid else None
        if payload is not None:
            idx = self._fmt.findData(payload.default_format)
            if idx >= 0:
                self._fmt.blockSignals(True)
                self._fmt.setCurrentIndex(idx)
                self._fmt.blockSignals(False)
            self._outfile.setPlaceholderText(f"auto: shell.{payload.default_ext}")
        self._rebuild()

    def _spec(self) -> msfvenom.MsfvenomSpec:
        return msfvenom.MsfvenomSpec(
            payload=self._payload.currentData() or "",
            fmt=self._fmt.currentData() or "",
            lhost=self._lhost.text().strip(),
            lport=int(self._lport.value()),
            encoder=self._encoder.currentData() or "",
            iterations=int(self._iterations.value()),
            badchars=self._badchars.text().strip(),
            outfile=self._outfile.text().strip(),
        )

    def _rebuild(self) -> None:
        result = msfvenom.build_command(self._spec())
        self._command.setPlainText(result.command)
        self._listener.setPlainText(result.listener)
        self._notes.setText("  ·  ".join(result.notes) if result.notes else "")

    @staticmethod
    def _copy(text: str, button: QPushButton) -> None:
        clip = QGuiApplication.clipboard()
        if clip is not None:
            clip.setText(text)
            styles.flash_copied(button)
