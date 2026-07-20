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
    accent="#8f6c15",  # deepened for WCAG-AA: accent-on-cream 4.31:1, white-on-accent 4.86:1
    accent_text="#ffffff",
    secondary="#3f6f74",
    focus="#8f6c15",
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

# Three extra RETICLE themes from the Nabu brand kit. Fields match Palette exactly, so the
# app_stylesheet() instrument layer renders them unchanged — no per-theme QSS needed.
LEET = Palette(  # matrix green on near-black
    bg="#050806",
    surface="#0a120c",
    surface_alt="#0f1b12",
    border="#1a3a22",
    text="#baffc6",
    text_muted="#5a9b6b",
    nav_label="#39ff14",
    accent="#39ff14",
    accent_text="#041006",
    secondary="#7dff5a",
    focus="#39ff14",
    selection="#0d2c17",
    success="#39ff14",
    warning="#d4ff3f",
    error="#ff5555",
    info="#7dff5a",
)

AMBER = Palette(  # amber CRT phosphor
    bg="#0b0700",
    surface="#150f04",
    surface_alt="#1e1607",
    border="#3d2f0e",
    text="#ffce88",
    text_muted="#b3854a",
    nav_label="#ffb000",
    accent="#ffb000",
    accent_text="#150f04",
    secondary="#ffd89a",
    focus="#ffb000",
    selection="#2c2008",
    success="#c6d84a",
    warning="#ffb000",
    error="#ff6a3d",
    info="#ffd89a",
)

SYNTHWAVE = Palette(  # neon magenta + cyan on deep violet
    bg="#150829",
    surface="#1e0f3d",
    surface_alt="#281450",
    border="#3d2170",
    text="#f6e9ff",
    text_muted="#a98fce",
    nav_label="#ffcf40",
    accent="#ff2fb9",
    accent_text="#1a0433",
    secondary="#26f0ff",
    focus="#ff2fb9",
    selection="#2f1560",
    success="#52e39b",
    warning="#ffcf40",
    error="#ff5c7a",
    info="#26f0ff",
)

# Six popular editor palettes people already know from their terminal / VS Code, so the theme
# picker feels familiar. Each rides the generic _fusion_palette() layer (no per-theme QSS) and is
# WCAG-AA-validated by test_theme_contrast for every contrast pair.
DRACULA = Palette(  # the classic purple-on-charcoal
    bg="#282a36",
    surface="#343746",
    surface_alt="#3d4055",
    border="#4d5066",
    text="#f8f8f2",
    text_muted="#9aa4d2",
    nav_label="#ff79c6",
    accent="#bd93f9",
    accent_text="#1a1428",
    secondary="#8be9fd",
    focus="#bd93f9",
    selection="#44475a",
    success="#50fa7b",
    warning="#f1fa8c",
    error="#ff5555",
    info="#8be9fd",
)

NORD = Palette(  # arctic blue-grey, frost accents
    bg="#2e3440",
    surface="#3b4252",
    surface_alt="#434c5e",
    border="#4c566a",
    text="#eceff4",
    text_muted="#c0c8d6",
    nav_label="#8fbcbb",
    accent="#88c0d0",
    accent_text="#16303a",
    secondary="#81a1c1",
    focus="#88c0d0",
    selection="#434c5e",
    success="#a3be8c",
    warning="#ebcb8b",
    error="#bf616a",
    info="#81a1c1",
)

GRUVBOX = Palette(  # warm retro — cream on brown-black, amber/orange accents
    bg="#282828",
    surface="#3c3836",
    surface_alt="#504945",
    border="#665c54",
    text="#ebdbb2",
    text_muted="#c4b596",
    nav_label="#fe8019",
    accent="#fabd2f",
    accent_text="#2a2000",
    secondary="#83a598",
    focus="#fabd2f",
    selection="#504945",
    success="#b8bb26",
    warning="#fabd2f",
    error="#fb4934",
    info="#83a598",
)

SOLARIZED = Palette(  # Solarized Dark — teal-ink ground, yellow accent
    bg="#002b36",
    surface="#073642",
    surface_alt="#0a4a5a",
    border="#0f5c6e",
    text="#eee8d5",
    text_muted="#93a1a1",
    nav_label="#2aa198",
    accent="#b58900",
    accent_text="#04212a",
    secondary="#268bd2",
    focus="#b58900",
    selection="#0a4a5a",
    success="#859900",
    warning="#cb4b16",
    error="#dc322f",
    info="#268bd2",
)

TOKYONIGHT = Palette(  # muted indigo night, soft blue accent
    bg="#1a1b26",
    surface="#24283b",
    surface_alt="#2f334d",
    border="#3b4261",
    text="#c0caf5",
    text_muted="#9099c4",
    nav_label="#7dcfff",
    accent="#7aa2f7",
    accent_text="#0d1020",
    secondary="#bb9af7",
    focus="#7aa2f7",
    selection="#2f334d",
    success="#9ece6a",
    warning="#e0af68",
    error="#f7768e",
    info="#7dcfff",
)

MONOKAI = Palette(  # the Sublime classic — lime-green accent on olive-charcoal
    bg="#272822",
    surface="#33342c",
    surface_alt="#3e3d32",
    border="#4d4c40",
    text="#f8f8f2",
    text_muted="#bcbcab",
    nav_label="#66d9ef",
    accent="#a6e22e",
    accent_text="#0f1a00",
    secondary="#f92672",
    focus="#a6e22e",
    selection="#3e3d32",
    success="#a6e22e",
    warning="#e6db74",
    error="#f92672",
    info="#66d9ef",
)


_PALETTES = {
    "dark": DARK,
    "light": LIGHT,
    "htb": HTB,
    "leet": LEET,
    "amber": AMBER,
    "synthwave": SYNTHWAVE,
    "dracula": DRACULA,
    "nord": NORD,
    "gruvbox": GRUVBOX,
    "solarized": SOLARIZED,
    "tokyonight": TOKYONIGHT,
    "monokai": MONOKAI,
}
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
