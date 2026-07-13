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


def app_version() -> str:
    try:
        return metadata.version(DIST_NAME)
    except metadata.PackageNotFoundError:
        return __version__
