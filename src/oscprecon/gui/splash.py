from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPixmap
from PySide6.QtWidgets import QSplashScreen

from oscprecon import __version__

_WORDMARK = r"""  ___  ___  ___ ___    ___ ___ ___ ___  _  _
 / _ \/ __|/ __| _ \  | _ \ __/ __/ _ \| \| |
| (_) \__ \ (__|  _/  |   / _| (_| (_) | .` |
 \___/|___/\___|_|    |_|_\___\___\___/|_|\_|"""

_BG = QColor("#0b0f14")
_ACCENT = QColor("#7fd1b9")
_MUTED = QColor("#6b7d8a")


def make_splash(width: int = 620, height: int = 300) -> QSplashScreen:
    pixmap = QPixmap(width, height)
    pixmap.fill(_BG)
    painter = QPainter(pixmap)

    mono = QFont("monospace")
    mono.setStyleHint(QFont.StyleHint.Monospace)
    mono.setPointSize(13)
    painter.setFont(mono)
    painter.setPen(_ACCENT)
    painter.drawText(
        pixmap.rect().adjusted(34, 46, -34, -104),
        int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop),
        _WORDMARK,
    )

    label = QFont()
    label.setPointSize(10)
    painter.setFont(label)
    painter.setPen(_MUTED)
    painter.drawText(
        pixmap.rect().adjusted(36, height - 86, -34, -22),
        int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop),
        f"v{__version__}   recon-first · OSCP exam-legal\nloading workspace…",
    )
    painter.end()

    splash = QSplashScreen(pixmap)
    splash.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
    return splash
