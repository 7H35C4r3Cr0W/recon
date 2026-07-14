from __future__ import annotations

from oscprecon.gui.theme import tokens
from oscprecon.gui.theme.tokens import Palette

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
