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
        f"   |)__)   v{app_version()} · recon-only by default · OSCP exam-legal\n"
        f'   -"-"-   offline · no exploitation · no AI at runtime\n'
    )
