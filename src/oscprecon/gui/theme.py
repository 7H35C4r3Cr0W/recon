from __future__ import annotations

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

# why: §19/§23 — a dark/light toggle for exam-day comfort. Fusion + a dark QPalette is the robust
# Qt way (complete coverage of every widget role, no fragile per-widget QSS to maintain).
THEMES = ("light", "dark")
DEFAULT_THEME = "light"


def _dark_palette() -> QPalette:
    dark = QColor(53, 53, 53)
    base = QColor(35, 35, 35)
    text = QColor(221, 221, 221)
    highlight = QColor(42, 130, 218)
    disabled = QColor(120, 120, 120)
    p = QPalette()
    p.setColor(QPalette.ColorRole.Window, dark)
    p.setColor(QPalette.ColorRole.WindowText, text)
    p.setColor(QPalette.ColorRole.Base, base)
    p.setColor(QPalette.ColorRole.AlternateBase, dark)
    p.setColor(QPalette.ColorRole.ToolTipBase, base)
    p.setColor(QPalette.ColorRole.ToolTipText, text)
    p.setColor(QPalette.ColorRole.Text, text)
    p.setColor(QPalette.ColorRole.Button, dark)
    p.setColor(QPalette.ColorRole.ButtonText, text)
    p.setColor(QPalette.ColorRole.BrightText, QColor(255, 80, 80))
    p.setColor(QPalette.ColorRole.Link, highlight)
    p.setColor(QPalette.ColorRole.Highlight, highlight)
    p.setColor(QPalette.ColorRole.HighlightedText, QColor(20, 20, 20))
    for role in (
        QPalette.ColorRole.Text,
        QPalette.ColorRole.ButtonText,
        QPalette.ColorRole.WindowText,
    ):
        p.setColor(QPalette.ColorGroup.Disabled, role, disabled)
    return p


def normalize(name: str) -> str:
    return name if name in THEMES else DEFAULT_THEME


def apply_theme(name: str) -> None:
    app = QApplication.instance()
    if not isinstance(app, QApplication):
        return
    if normalize(name) == "dark":
        app.setStyle("Fusion")
        app.setPalette(_dark_palette())
    else:
        app.setPalette(app.style().standardPalette())
