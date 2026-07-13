from __future__ import annotations

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen, QPixmap
from PySide6.QtWidgets import QSplashScreen

from oscprecon import __version__
from oscprecon.branding import APP_NAME, APP_SUBTITLE, APP_TAGLINE
from oscprecon.gui.theme import tokens

# Nabu palette from the shared design tokens (single source of truth) — deep ink/navy field,
# gold/bronze accent, muted teal secondary. The mark is an original network-graph motif.
_BG = QColor(tokens.DARK.bg)
_PANEL = QColor(tokens.DARK.surface)
_GOLD = QColor(tokens.DARK.accent)
_TEAL = QColor(tokens.DARK.secondary)
_TEXT = QColor(tokens.DARK.text)
_MUTED = QColor(tokens.DARK.text_muted)


def _draw_mark(painter: QPainter, cx: float, cy: float, r: float) -> None:
    # small constellation: three satellites around a hub, edges first so nodes sit on top
    hub = QPointF(cx, cy)
    sats = [
        QPointF(cx - r, cy - r * 0.55),
        QPointF(cx + r * 0.9, cy - r * 0.2),
        QPointF(cx - r * 0.15, cy + r),
    ]
    painter.setPen(QPen(_TEAL, 2))
    for s in sats:
        painter.drawLine(hub, s)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(_GOLD)
    painter.drawEllipse(hub, 7.0, 7.0)
    painter.setBrush(_TEAL)
    for s in sats:
        painter.drawEllipse(s, 4.5, 4.5)


def make_splash(width: int = 620, height: int = 300) -> QSplashScreen:
    pixmap = QPixmap(width, height)
    pixmap.fill(_BG)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    # framed inner panel for a finished, product feel
    painter.setPen(QPen(_PANEL, 2))
    painter.setBrush(_PANEL)
    painter.drawRoundedRect(pixmap.rect().adjusted(16, 16, -16, -16), 10, 10)

    _draw_mark(painter, 74.0, 96.0, 34.0)

    wordmark = QFont()
    wordmark.setPointSize(40)
    wordmark.setWeight(QFont.Weight.DemiBold)
    painter.setFont(wordmark)
    painter.setPen(_TEXT)
    painter.drawText(128, 112, APP_NAME)

    tagline = QFont()
    tagline.setPointSize(12)
    painter.setFont(tagline)
    painter.setPen(_GOLD)
    painter.drawText(130, 140, APP_TAGLINE)

    footer = QFont()
    footer.setPointSize(10)
    painter.setFont(footer)
    painter.setPen(_MUTED)
    painter.drawText(
        pixmap.rect().adjusted(36, height - 78, -34, -22),
        int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop),
        f"v{__version__}   {APP_SUBTITLE}\nloading workspace…",
    )
    painter.end()

    splash = QSplashScreen(pixmap)
    splash.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
    return splash
