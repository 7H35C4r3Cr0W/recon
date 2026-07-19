from __future__ import annotations

from importlib import metadata

from oscprecon import __version__

# why: the user-facing product is "Nabu"; the internal Python package stays `oscprecon` and the
# distribution/wheel name stays `oscp-recon` so installs, imports, and data paths keep working. This
# module is the single source of truth for the display brand — surfaces import from here, never
# hard-code the string.
APP_NAME = "Nabu"
APP_TAGLINE = "Local Recon Workspace"
APP_SUBTITLE = "recon-first · OSCP exam-legal"
DIST_NAME = "oscp-recon"

# Author / maintainer attribution — the single source of truth, surfaced on every brand surface
# (GUI header watermark + About dialog, CLI banner + `--version`). Edit here only.
AUTHOR_NAME = "Andre Boyle"
AUTHOR_EMAIL = "its.lagus@proton.me"
AUTHOR_GITHUB = "https://github.com/7H35C4r3Cr0W/recon"
AUTHOR_CREDIT = f"{AUTHOR_NAME} · {AUTHOR_EMAIL}"


def author_line() -> str:
    """One-line credit for banners/footers: 'Nabu by Andre Boyle · its.lagus@proton.me'."""
    return f"{APP_NAME} by {AUTHOR_NAME} · {AUTHOR_EMAIL}"


# the Nabu mascot — a little owl-furby (Nabu, god of scribes & wisdom → owl). The GUI shows the SVG
# version top-right; this is the CLI's text incarnation. Purely cosmetic.
FURBY_ASCII = r"""   {o,o}
   |)__)
   -"-"-"""


def app_version() -> str:
    try:
        return metadata.version(DIST_NAME)
    except metadata.PackageNotFoundError:
        return __version__


def cli_banner() -> str:
    """A small owl-furby banner for the CLI. Cosmetic; callers print it to stderr on a real TTY."""
    return (
        f"   {{o,o}}   {APP_NAME} — {APP_TAGLINE}\n"
        f"   |)__)   v{app_version()} · recon-first · OSCP exam-legal by default\n"
        f'   -"-"-   by {AUTHOR_NAME} · {AUTHOR_EMAIL}\n'
        f"           {AUTHOR_GITHUB}\n"
    )
