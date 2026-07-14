from __future__ import annotations

from dataclasses import dataclass

# Nabu design tokens — the single, typed source of truth for colour, spacing, radius, sizing and
# type. Widgets read tokens instead of hard-coding hexes so the look stays consistent and both
# themes stay in sync. Strong colours (accent, success/warning/error) are reserved for primary
# actions, active nav, selection and verified/warning states — never decoration.


@dataclass(frozen=True)
class Palette:
    bg: str  # window background
    surface: str  # panels / cards
    surface_alt: str  # inset / alternating rows
    border: str
    text: str
    text_muted: str
    accent: str  # gold/bronze — primary action, active nav, selection
    accent_text: str  # legible text on top of `accent`
    secondary: str  # muted teal — secondary emphasis
    focus: str  # keyboard focus ring
    selection: str  # selected-row background
    success: str  # confirmed / reachable
    warning: str  # relay-risk / misconfig
    error: str  # failure / blocked
    info: str  # neutral notable


DARK = Palette(
    bg="#0f1420",
    surface="#161d2b",
    surface_alt="#1b2434",
    border="#2a3446",
    text="#e6e9ef",
    text_muted="#8a94a6",
    accent="#c9a227",
    accent_text="#0f1420",
    secondary="#5b8a8f",
    focus="#c9a227",
    selection="#243044",
    success="#5b8f6a",
    warning="#c9a227",
    error="#c0564b",
    info="#5b8a8f",
)

LIGHT = Palette(
    bg="#f4f1ea",
    surface="#ffffff",
    surface_alt="#efeadd",
    border="#d8d2c4",
    text="#1b2230",
    text_muted="#5c6675",
    accent="#b3891f",
    accent_text="#ffffff",
    secondary="#3f6f74",
    focus="#b3891f",
    selection="#e6dcc4",
    success="#3f7a52",
    warning="#b3891f",
    error="#a5342a",
    info="#3f6f74",
)


# HTB — a Hack The Box-flavoured dark theme: deep navy ground with the signature acid-green accent.
# Green carries active nav / focus / selection / links; gold-ish warnings and a hot-pink error stay
# legible on the navy so state never rides on the green alone.
HTB = Palette(
    bg="#111927",
    surface="#1a2432",
    surface_alt="#202c3d",
    border="#2b3a52",
    text="#e6edf6",
    text_muted="#8698b3",
    accent="#9fef00",  # the Hack The Box green
    accent_text="#0a1200",
    secondary="#5cb8ff",
    focus="#9fef00",
    selection="#1d3a26",  # green-tinted selected row
    success="#3ddc84",
    warning="#f5c518",
    error="#ff5c7a",
    info="#5cb8ff",
)

_PALETTES = {"dark": DARK, "light": LIGHT, "htb": HTB}


def palette(theme: str) -> Palette:
    return _PALETTES.get(theme, LIGHT)


# spacing scale (px) — use these, not magic margins
SPACE_XS = 4
SPACE_SM = 8
SPACE_MD = 12
SPACE_LG = 16
SPACE_XL = 24

# corner radius (px)
RADIUS_SM = 4
RADIUS_MD = 8
RADIUS_LG = 12

# control + icon sizing (px)
CONTROL_HEIGHT = 28
ICON_SM = 16
ICON_MD = 20
ICON_LG = 24

# typography — system fonts only (never bundle fonts). A stack, not one family, so it resolves on
# Kali/Linux, macOS and Windows.
FONT_STACK = "'Segoe UI', 'Helvetica Neue', 'Noto Sans', 'DejaVu Sans', Arial, sans-serif"
MONO_STACK = "'JetBrains Mono', 'DejaVu Sans Mono', 'Menlo', 'Consolas', monospace"
FONT_SIZE_SM = 11
FONT_SIZE_MD = 13
FONT_SIZE_LG = 16
FONT_SIZE_TITLE = 22
