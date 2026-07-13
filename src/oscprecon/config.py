from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

APP_NAME = "oscprecon"
DEFAULT_WORKSPACE = Path.home() / "oscprecon"
RECENT_LIMIT = 10


def config_dir() -> Path:
    raw = os.environ.get("XDG_CONFIG_HOME")
    base = Path(raw) if raw else Path.home() / ".config"
    directory = base / APP_NAME
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _prefs_path() -> Path:
    return config_dir() / "prefs.json"


def _recent_path() -> Path:
    return config_dir() / "recent.json"


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _write_json_atomic(path: Path, obj: Any) -> None:
    # why: mirror profile.json/creds.json — a crash mid-write must not truncate the config file.
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    tmp.replace(path)


def load_prefs() -> dict[str, str]:
    data = _read_json(_prefs_path(), {})
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items()}


def save_prefs(prefs: dict[str, str]) -> None:
    _write_json_atomic(_prefs_path(), prefs)


def workspace_root() -> Path:
    return Path(load_prefs().get("workspace_root", str(DEFAULT_WORKSPACE)))


def recent_profiles() -> list[str]:
    data = _read_json(_recent_path(), [])
    if not isinstance(data, list):
        return []
    return [str(p) for p in data]


def add_recent(profile_dir: Path) -> None:
    entry = str(Path(profile_dir).resolve())
    items = [p for p in recent_profiles() if p != entry]
    items.insert(0, entry)
    del items[RECENT_LIMIT:]
    _write_json_atomic(_recent_path(), items)
