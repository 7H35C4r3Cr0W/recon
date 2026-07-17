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
    nav_label: str  # left nav-rail label/icon — brighter than text_muted for legibility
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
    nav_label="#f0c94b",  # bright warm gold — readable at a glance on the dark rail
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
    nav_label="#7a5c0f",  # dark goldenrod — warm but readable on the light cream rail
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


# HTB — a Hack-The-Box / Parrot-OS-flavoured dark theme: dark teal-slate ground with Parrot
# Security's signature cyan-green accent (#15e4f1). The accent carries active nav / focus /
# selection / links AND the primary action buttons; amber warnings and a hot-pink error stay
# legible on the dark so state never rides on the green alone.
HTB = Palette(
    # The DEFAULT theme — a Hack-The-Box / Parrot-OS flavour: a deep navy-teal ground with Parrot
    # Security's signature cyan-green accent (#15e4f1) and a bright light-blue (#5cc8ff / #6fd6ff)
    # carrying nav labels, links and secondary emphasis. Gold-free by design; state rides on the
    # cyan accent + semantic green/amber/pink so a status can never be mistaken for the accent.
    bg="#0b1622",  # deep navy-teal — richer contrast for the neon accent to sit on
    surface="#12202f",  # cards / panels
    surface_alt="#1a2c40",  # inset / alternating rows — a touch lighter for definition
    border="#26394f",
    text="#e6eff6",  # crisp near-white
    text_muted="#8598ac",
    nav_label="#6fd6ff",  # bright light-blue — nav-rail labels, distinct from the cyan accent
    accent="#15e4f1",  # Parrot Security cyan-green (the primary "live"/CTA colour)
    accent_text="#052227",  # legible dark on the neon accent
    secondary="#5cc8ff",  # light blue — links / secondary emphasis
    focus="#15e4f1",
    selection="#163241",  # cyan-tinted selected row
    success="#3ddc84",
    warning="#f5c518",
    error="#ff5c7a",
    info="#5cc8ff",
)

_PALETTES = {"dark": DARK, "light": LIGHT, "htb": HTB}
_active_theme = "htb"  # HTB / Parrot is the default look (set by theme.apply_theme on startup)


def palette(theme: str) -> Palette:
    return _PALETTES.get(theme, LIGHT)


def set_active_theme(name: str) -> None:
    # why: lets primary buttons pick up the CURRENT theme's accent (green in HTB) without threading
    # the theme name through every constructor. Set by theme.apply_theme().
    global _active_theme
    _active_theme = name if name in _PALETTES else "light"


def active_palette() -> Palette:
    return _PALETTES.get(_active_theme, LIGHT)


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
