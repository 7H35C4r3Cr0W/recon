from __future__ import annotations

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

# why: §19/§23 — a dark/light toggle for exam-day comfort. Fusion + a dark QPalette is the robust
# Qt way (complete coverage of every widget role, no fragile per-widget QSS to maintain).
THEMES = ("light", "dark", "htb")
DEFAULT_THEME = "light"
_LABELS = {"light": "Light", "dark": "Dark", "htb": "HTB"}


def label(name: str) -> str:
    """Human display name for a theme (so 'htb' shows as 'HTB', not 'Htb')."""
    return _LABELS.get(name, name.capitalize())


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


def _htb_palette() -> QPalette:
    # Hack The Box flavour — deep navy ground, acid-green highlight. Mirrors _dark_palette's roles
    # so every Fusion-drawn widget (tables, inputs) reads correctly on the navy.
    bg = QColor("#111927")
    base = QColor("#1a2432")
    text = QColor("#e6edf6")
    green = QColor("#9fef00")
    disabled = QColor("#6b7688")
    p = QPalette()
    p.setColor(QPalette.ColorRole.Window, bg)
    p.setColor(QPalette.ColorRole.WindowText, text)
    p.setColor(QPalette.ColorRole.Base, base)
    p.setColor(QPalette.ColorRole.AlternateBase, QColor("#202c3d"))
    p.setColor(QPalette.ColorRole.ToolTipBase, base)
    p.setColor(QPalette.ColorRole.ToolTipText, text)
    p.setColor(QPalette.ColorRole.Text, text)
    p.setColor(QPalette.ColorRole.Button, base)
    p.setColor(QPalette.ColorRole.ButtonText, text)
    p.setColor(QPalette.ColorRole.BrightText, QColor("#ff5c7a"))
    p.setColor(QPalette.ColorRole.Link, QColor("#5cb8ff"))
    p.setColor(QPalette.ColorRole.Highlight, green)
    p.setColor(QPalette.ColorRole.HighlightedText, QColor("#0a1200"))
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
    normalized = normalize(name)
    if normalized == "dark":
        app.setStyle("Fusion")
        app.setPalette(_dark_palette())
    elif normalized == "htb":
        app.setStyle("Fusion")
        app.setPalette(_htb_palette())
    else:
        app.setPalette(app.style().standardPalette())


_default_point_size: int | None = None


def apply_font(point_size: int) -> None:
    # point_size <= 0 means "restore the Qt default" — captured once on first call so the override
    # is fully reversible without an app restart.
    global _default_point_size
    app = QApplication.instance()
    if not isinstance(app, QApplication):
        return
    font = app.font()
    if _default_point_size is None:
        _default_point_size = font.pointSize()
    font.setPointSize(point_size if point_size > 0 else _default_point_size)
    app.setFont(font)
