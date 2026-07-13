from __future__ import annotations

from pathlib import Path

# why: original, locally bundled Nabu identity (cuneiform-tablet + network-graph motif). No external
# fetch, no copyrighted artwork. Resolve package-relative so it works installed or in-tree.
ASSETS_DIR = Path(__file__).parent

LOGO = "logo.svg"
ICON = "icon.svg"
ICON_LIGHT = "icon-light.svg"
ICON_MONO = "icon-mono.svg"
SPLASH = "splash.svg"
EMPTY_WORKSPACE = "empty-workspace.svg"


def asset_path(name: str) -> Path:
    return ASSETS_DIR / name
