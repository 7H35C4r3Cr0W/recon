from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QAbstractButton

from oscprecon.gui.theme import tokens
from oscprecon.gui.theme.tokens import Palette


def flash_copied(button: QAbstractButton, *, ms: int = 1200) -> None:
    # visible feedback for a clipboard copy (setting the clipboard is otherwise invisible): flash
    # the button to "Copied ✓" then restore. The button is the timer's context object, so if it's
    # destroyed before the timer fires (dialog closed), the restore is auto-cancelled (no crash).
    original = button.text()
    button.setText("Copied ✓")
    QTimer.singleShot(ms, button, lambda: button.setText(original))


# Small, composable QSS builders derived from tokens. Widgets call these instead of pasting hex
# strings, so hover/pressed/focus states stay uniform. Each returns a QSS snippet (a str); nothing
# here touches the QApplication — callers apply the result with setStyleSheet.

# semantic status kinds -> the palette field that colours them (colour-independent status also uses
# a text label; colour alone must never be the only signal — see accessibility notes)
STATUS_FIELDS = {
    "success": "success",
    "warning": "warning",
    "error": "error",
    "info": "info",
    "accent": "accent",
    "muted": "text_muted",
}


def status_color(kind: str, pal: Palette) -> str:
    return str(getattr(pal, STATUS_FIELDS.get(kind, "info")))


# why: these button styles are applied once with a fixed palette (a gold CTA is intentionally the
# same in both themes), so the disabled state must be theme-NEUTRAL — a palette-bound surface_alt
# would paint a dark-navy chip in the light default theme. Translucent grey reads on both grounds.
_DISABLED = " QPushButton:disabled { background:rgba(128,128,128,0.16);"
_DISABLED += " color:rgba(128,128,128,0.85); border-color:rgba(128,128,128,0.35); }"


def primary_button(pal: Palette) -> str:
    return (
        "QPushButton {"
        f" background:{pal.accent}; color:{pal.accent_text};"
        f" border:none; border-radius:{tokens.RADIUS_SM}px;"
        f" padding:6px {tokens.SPACE_MD}px; min-height:{tokens.CONTROL_HEIGHT}px;"
        " font-weight:600; }"
        f" QPushButton:hover {{ background:{_lighten(pal.accent)}; }}"
        f" QPushButton:pressed {{ background:{_darken(pal.accent)}; }}"
        f" QPushButton:focus {{ outline:none; border:2px solid {pal.focus}; }}" + _DISABLED
    )


def accent_button() -> str:
    """primary_button() in the ACTIVE theme's accent — so CTAs turn cyan-green in HTB mode."""
    return primary_button(tokens.active_palette())


def accent_tool_button() -> str:
    """accent_button() styling applied to a QToolButton (a split/menu button keeps the CTA look)."""
    base = accent_button().replace("QPushButton", "QToolButton")
    # keep the ▾ menu indicator visible (a distinct right-hand region) so the dropdown is found
    return base + (
        f" QToolButton::menu-button {{ border:none; width:18px;"
        f" border-top-right-radius:{tokens.RADIUS_SM}px;"
        f" border-bottom-right-radius:{tokens.RADIUS_SM}px; }}"
    )


def secondary_button(pal: Palette) -> str:
    return (
        "QPushButton {"
        f" background:{pal.surface}; color:{pal.text};"
        f" border:1px solid {pal.border}; border-radius:{tokens.RADIUS_SM}px;"
        f" padding:6px {tokens.SPACE_MD}px; min-height:{tokens.CONTROL_HEIGHT}px; }}"
        f" QPushButton:hover {{ border-color:{pal.accent}; }}"
        f" QPushButton:pressed {{ background:{pal.surface_alt}; }}"
        f" QPushButton:focus {{ border:2px solid {pal.focus}; }}" + _DISABLED
    )


def danger_button(pal: Palette) -> str:
    # outline-danger: error-coloured border+text, fills on hover — destructive without shouting
    return (
        "QPushButton {"
        f" background:transparent; color:{pal.error};"
        f" border:1px solid {pal.error}; border-radius:{tokens.RADIUS_SM}px;"
        f" padding:6px {tokens.SPACE_MD}px; min-height:{tokens.CONTROL_HEIGHT}px; }}"
        f" QPushButton:hover {{ background:{pal.error}; color:{pal.bg}; }}"
        f" QPushButton:pressed {{ background:{_darken(pal.error)}; }}"
        f" QPushButton:focus {{ border:2px solid {pal.focus}; }}" + _DISABLED
    )


def badge(kind: str, pal: Palette) -> str:
    color = status_color(kind, pal)
    return (
        "QLabel {"
        f" color:{color}; border:1px solid {color}; border-radius:{tokens.RADIUS_SM}px;"
        f" padding:1px {tokens.SPACE_SM}px; font-size:{tokens.FONT_SIZE_SM}px; }}"
    )


def focus_ring(pal: Palette) -> str:
    return f"*:focus {{ outline:none; border:2px solid {pal.focus}; }}"


def app_stylesheet(theme_name: str) -> str:
    """A global 'precision-instrument' QSS (the RETICLE look) applied to the whole QApplication.

    It restyles the PLAIN base widgets (scroll-bars, headers, tables/trees, tabs, inputs, group
    boxes, menus, tool-tips, splitters, un-styled buttons) to a machined-panel aesthetic derived
    from the active palette — the accent is rationed to focus/hover/selection/active state. Custom
    widgets that set their own stylesheet keep their look (widget QSS wins over the app QSS), so
    this never fights the panels; it only elevates everything Fusion drew plainly."""
    p = tokens.palette(theme_name)
    r = tokens.RADIUS_SM
    accent_soft = _mix(p.accent, p.surface, 0.22)  # a faint accent tint for hover grounds
    return f"""
    /* recessed 'wells' — inputs read as milled insets with a cyan focus edge */
    QLineEdit, QPlainTextEdit, QTextEdit, QAbstractSpinBox {{
        background:{p.surface_alt}; color:{p.text};
        border:1px solid {p.border}; border-radius:{r}px; padding:3px 6px;
        selection-background-color:{p.accent}; selection-color:{p.accent_text}; }}
    QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QAbstractSpinBox:focus {{
        border:1px solid {p.accent}; }}
    QComboBox {{
        background:{p.surface_alt}; color:{p.text}; border:1px solid {p.border};
        border-radius:{r}px; padding:3px 6px; }}
    QComboBox:focus, QComboBox:on {{ border:1px solid {p.accent}; }}
    QComboBox QAbstractItemView {{
        background:{p.surface}; color:{p.text}; border:1px solid {p.border};
        selection-background-color:{p.selection}; selection-color:{p.text}; }}

    /* tables / trees — an instrument grid with a cyan-tinted selection */
    QTreeView, QTableView, QTreeWidget, QTableWidget, QListView, QListWidget {{
        background:{p.surface}; alternate-background-color:{p.surface_alt};
        gridline-color:{p.border}; border:1px solid {p.border}; border-radius:{r}px; }}
    QTreeView::item:selected, QTableView::item:selected, QTreeWidget::item:selected,
    QTableWidget::item:selected, QListView::item:selected, QListWidget::item:selected {{
        background:{p.selection}; color:{p.text}; }}
    QTreeView::item:hover, QTableView::item:hover, QListView::item:hover {{
        background:{accent_soft}; }}
    QHeaderView::section {{
        background:{p.surface_alt}; color:{p.text_muted}; border:none;
        border-right:1px solid {p.border}; border-bottom:1px solid {p.border};
        padding:4px 8px; font-weight:600; letter-spacing:1px; }}
    QTableCornerButton::section {{ background:{p.surface_alt}; border:none; }}

    /* tabs — flat, with a cyan active underline */
    QTabWidget::pane {{ border:1px solid {p.border}; border-radius:{r}px; top:-1px; }}
    QTabBar::tab {{
        background:transparent; color:{p.text_muted}; padding:6px 14px;
        border:none; border-bottom:2px solid transparent; margin-right:2px; }}
    QTabBar::tab:selected {{ color:{p.accent}; border-bottom:2px solid {p.accent}; }}
    QTabBar::tab:hover:!selected {{ color:{p.text}; }}

    /* group boxes — a titled faceplate */
    QGroupBox {{
        border:1px solid {p.border}; border-radius:{tokens.RADIUS_MD}px;
        margin-top:12px; padding-top:8px; }}
    QGroupBox::title {{
        subcontrol-origin:margin; subcontrol-position:top left; left:10px; padding:0 5px;
        color:{p.text_muted}; font-weight:700; }}

    /* base buttons (only where a widget hasn't set its own) */
    QPushButton {{
        background:{p.surface}; color:{p.text}; border:1px solid {p.border};
        border-radius:{r}px; padding:5px 12px; }}
    QPushButton:hover {{ border-color:{p.accent}; color:{p.accent}; }}
    QPushButton:pressed {{ background:{p.surface_alt}; }}
    QPushButton:disabled {{
        color:{p.text_muted}; border-color:{p.border}; background:transparent; }}

    /* thin instrument scroll-bars — cyan on hover */
    QScrollBar:vertical {{ background:transparent; width:11px; margin:0; }}
    QScrollBar:horizontal {{ background:transparent; height:11px; margin:0; }}
    QScrollBar::handle:vertical {{ background:{p.border}; border-radius:5px; min-height:26px; }}
    QScrollBar::handle:horizontal {{ background:{p.border}; border-radius:5px; min-width:26px; }}
    QScrollBar::handle:hover {{ background:{p.accent}; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width:0; height:0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background:transparent; }}

    /* menus / bar / tool-tips */
    QMenuBar {{ background:{p.surface}; color:{p.text}; }}
    QMenuBar::item {{ padding:4px 10px; background:transparent; }}
    QMenuBar::item:selected {{ background:{p.selection}; color:{p.accent}; }}
    QMenu {{ background:{p.surface}; color:{p.text}; border:1px solid {p.border}; }}
    QMenu::item {{ padding:5px 22px; }}
    QMenu::item:selected {{ background:{p.selection}; color:{p.accent}; }}
    QMenu::separator {{ height:1px; background:{p.border}; margin:4px 8px; }}
    QToolTip {{
        background:{p.surface_alt}; color:{p.text}; border:1px solid {p.accent}; padding:3px 6px; }}

    /* splitter grip — glows cyan on hover */
    QSplitter::handle {{ background:{p.border}; }}
    QSplitter::handle:hover {{ background:{p.accent}; }}
    """


def _mix(a: str, b: str, t: float) -> str:
    # linear blend a->b by t (0..1) — for faint accent-tinted hover grounds.
    ah, bh = a.lstrip("#"), b.lstrip("#")
    if len(ah) != 6 or len(bh) != 6:
        return b
    out = []
    for i in (0, 2, 4):
        av, bv = int(ah[i : i + 2], 16), int(bh[i : i + 2], 16)
        out.append(_clamp(round(av * t + bv * (1 - t))))
    return f"#{out[0]:02x}{out[1]:02x}{out[2]:02x}"


def _clamp(v: int) -> int:
    return max(0, min(255, v))


def _shift(hex_color: str, delta: int) -> str:
    h = hex_color.lstrip("#")
    if len(h) != 6:
        return hex_color
    r, g, b = (int(h[i : i + 2], 16) for i in (0, 2, 4))
    return f"#{_clamp(r + delta):02x}{_clamp(g + delta):02x}{_clamp(b + delta):02x}"


def _lighten(hex_color: str) -> str:
    return _shift(hex_color, 20)


def _darken(hex_color: str) -> str:
    return _shift(hex_color, -25)
