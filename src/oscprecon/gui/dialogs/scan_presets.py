from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from oscprecon.manual_commands import ManualCommand, expand


class ScanPresetsDialog(QDialog):
    """A browsable nmap-preset chooser. Highlight a scan on the left and its note ("what it's for")
    plus the exact command appear on the right — so you always see WHY before you Load or Run it.

    Recon-only (§8): every preset is plain nmap. `mode()` is 'load' (pre-fill the command builder),
    'run' (execute this nmap scan against the entry target), or None (cancelled)."""

    def __init__(
        self, presets: list[ManualCommand], target: str, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Nmap scan options")
        self.resize(760, 460)
        self._presets = presets
        self._target = target
        self._mode: str | None = None
        self._command = ""

        intro = QLabel(
            "Pick a scan for the situation — the note under it says what it's for. "
            "<b>Load into builder</b> pre-fills the command (review, then Run); "
            "<b>Run scan ▸</b> runs this nmap scan against the target now."
        )
        intro.setWordWrap(True)

        self._list = QListWidget()
        self._list.setMinimumWidth(300)
        for preset in presets:
            item = QListWidgetItem(preset.description)
            item.setToolTip(preset.why)
            self._list.addItem(item)
        self._list.currentRowChanged.connect(self._on_row)

        self._desc = QLabel("")
        self._desc.setWordWrap(True)
        self._desc.setStyleSheet("font-weight: 600; font-size: 14px;")
        self._why = QLabel("")
        self._why.setWordWrap(True)
        self._why.setStyleSheet("color: palette(mid);")
        self._cmd = QPlainTextEdit()
        self._cmd.setReadOnly(True)
        self._cmd.setMaximumHeight(80)
        self._cmd.setStyleSheet("font-family: monospace;")

        right = QVBoxLayout()
        right.addWidget(self._desc)
        right.addWidget(self._why)
        right.addWidget(QLabel("Command:"))
        right.addWidget(self._cmd)
        right.addStretch(1)
        right_box = QWidget()
        right_box.setLayout(right)

        top = QHBoxLayout()
        top.addWidget(self._list)
        top.addWidget(right_box, stretch=1)

        self._load_btn = QPushButton("Load into builder")
        self._load_btn.clicked.connect(lambda: self._finish("load"))
        self._run_btn = QPushButton("Run scan ▸")
        self._run_btn.clicked.connect(lambda: self._finish("run"))
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(cancel)
        buttons.addWidget(self._load_btn)
        buttons.addWidget(self._run_btn)

        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(top, stretch=1)
        layout.addLayout(buttons)

        if presets:
            self._list.setCurrentRow(0)
        else:
            self._set_enabled(False)

    def _set_enabled(self, on: bool) -> None:
        self._load_btn.setEnabled(on)
        self._run_btn.setEnabled(on)

    def _on_row(self, row: int) -> None:
        if row < 0 or row >= len(self._presets):
            self._set_enabled(False)
            return
        preset = self._presets[row]
        self._set_enabled(True)
        self._desc.setText(preset.description)
        self._why.setText(preset.why)
        self._command = expand(preset.command, target=self._target)
        self._cmd.setPlainText(self._command)

    def _finish(self, mode: str) -> None:
        row = self._list.currentRow()
        if row < 0 or row >= len(self._presets):
            return
        self._mode = mode
        self.accept()

    def mode(self) -> str | None:
        return self._mode

    def command(self) -> str:
        return self._command
