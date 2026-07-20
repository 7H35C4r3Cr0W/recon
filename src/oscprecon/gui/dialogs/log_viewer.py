from __future__ import annotations

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices, QFont
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from oscprecon import diagnostics


class LogViewerDialog(QDialog):
    """Read-only view of the diagnostic log — the newest entries first port of call when something
    breaks. Shows the tail of the rotating log with buttons to refresh, reveal the folder, or clear.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Nabu · Diagnostics log")
        self.resize(760, 480)

        self._path_label = QLabel()
        self._path_label.setTextInteractionFlags(
            self._path_label.textInteractionFlags().TextSelectableByMouse
        )
        self._path_label.setWordWrap(True)

        self._view = QPlainTextEdit()
        self._view.setReadOnly(True)
        self._view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        mono = QFont("monospace")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self._view.setFont(mono)

        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._reload)
        open_folder = QPushButton("Open log folder")
        open_folder.clicked.connect(self._open_folder)
        clear = QPushButton("Clear log")
        clear.clicked.connect(self._clear)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)

        buttons = QHBoxLayout()
        buttons.addWidget(refresh)
        buttons.addWidget(open_folder)
        buttons.addWidget(clear)
        buttons.addStretch(1)
        buttons.addWidget(close)

        layout = QVBoxLayout(self)
        layout.addWidget(self._path_label)
        layout.addWidget(self._view, stretch=1)
        layout.addLayout(buttons)

        self._reload()

    def _reload(self) -> None:
        self._path_label.setText(f"Log file: {diagnostics.log_path()}")
        text = diagnostics.read_tail()
        self._view.setPlainText(text or "(no log entries yet — nothing has gone wrong)")
        # jump to the newest entries at the bottom
        scrollbar = self._view.verticalScrollBar()
        if scrollbar is not None:
            scrollbar.setValue(scrollbar.maximum())

    def _open_folder(self) -> None:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(diagnostics.log_dir())))

    def _clear(self) -> None:
        confirm = QMessageBox.question(
            self,
            "Clear log",
            "Clear the current diagnostic log? Rotated backups are kept.",
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        if diagnostics.clear():
            self._reload()
        else:
            QMessageBox.warning(self, "Clear log", "Could not clear the log file.")
