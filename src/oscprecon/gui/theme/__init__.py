from __future__ import annotations

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

from oscprecon.gui.theme import tokens

# why: §19/§23 — a dark/light toggle for exam-day comfort. Fusion + a dark QPalette is the robust
# Qt way (complete coverage of every widget role, no fragile per-widget QSS to maintain).
THEMES = ("light", "dark", "htb")
# HTB / Parrot is the default look (owner request, 2026-07-16) — a deep navy-teal ground with the
# Parrot cyan-green accent + a light-blue secondary. Light + Dark remain for exam-day comfort.
DEFAULT_THEME = "htb"
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
    # HTB / Parrot-OS flavour (the default) — deep navy-teal ground, Parrot cyan-green highlight,
    # light-blue links. Mirrors tokens.HTB so every Fusion widget (tables, inputs) reads right.
    bg = QColor("#0b1622")
    base = QColor("#12202f")
    text = QColor("#e6eff6")
    green = QColor("#15e4f1")  # Parrot Security cyan-green
    disabled = QColor("#7f95a3")
    p = QPalette()
    p.setColor(QPalette.ColorRole.Window, bg)
    p.setColor(QPalette.ColorRole.WindowText, text)
    p.setColor(QPalette.ColorRole.Base, base)
    p.setColor(QPalette.ColorRole.AlternateBase, QColor("#1a2c40"))
    p.setColor(QPalette.ColorRole.ToolTipBase, base)
    p.setColor(QPalette.ColorRole.ToolTipText, text)
    p.setColor(QPalette.ColorRole.Text, text)
    p.setColor(QPalette.ColorRole.Button, base)
    p.setColor(QPalette.ColorRole.ButtonText, text)
    p.setColor(QPalette.ColorRole.BrightText, QColor("#ff5c7a"))
    p.setColor(QPalette.ColorRole.Link, QColor("#5cc8ff"))
    p.setColor(QPalette.ColorRole.Highlight, green)
    p.setColor(QPalette.ColorRole.HighlightedText, QColor("#04181c"))
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
    tokens.set_active_theme(normalized)  # so primary buttons pick up this theme's accent
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
