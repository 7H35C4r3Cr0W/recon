"""Adapter configuration.

Kept tiny and env-driven. The engine has its OWN settings (oscprecon.config); we deliberately
do NOT reuse ~/.config/oscprecon/prefs.json — Nabu Agent's gates (spray/exploit) are per-project
and live in Postgres, not an app-wide pref file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# Env keys (documented for the API/ops dimension).
ENV_WORKSPACE_ROOT = "NABU_AGENT_WORKSPACE_ROOT"
ENV_TOOL_TIMEOUT = "NABU_AGENT_TOOL_TIMEOUT_S"
ENV_HACKTRICKS_LIVE = "NABU_AGENT_HACKTRICKS_LIVE"  # owner opt-in; default off

_DEFAULT_ROOT = Path("/var/lib/nabu-agent/workspaces")


@dataclass(frozen=True)
class EngineSettings:
    workspace_root: Path = _DEFAULT_ROOT
    default_tool_timeout_s: float = 600.0
    hacktricks_live_enabled: bool = False


def load_engine_settings() -> EngineSettings:
    root = os.environ.get(ENV_WORKSPACE_ROOT)
    timeout = os.environ.get(ENV_TOOL_TIMEOUT)
    live = os.environ.get(ENV_HACKTRICKS_LIVE, "").lower() in {"1", "true", "yes"}
    return EngineSettings(
        workspace_root=Path(root) if root else _DEFAULT_ROOT,
        default_tool_timeout_s=float(timeout) if timeout else 600.0,
        hacktricks_live_enabled=live,
    )
