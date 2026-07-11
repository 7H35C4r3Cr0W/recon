from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def findings_path(profile_dir: Path) -> Path:
    return Path(profile_dir) / "findings.json"


def load_findings(profile_dir: Path) -> list[dict[str, Any]]:
    path = findings_path(profile_dir)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def _key(finding: dict[str, Any]) -> tuple[Any, Any, Any, Any]:
    return (finding.get("module"), finding.get("port"), finding.get("path"), finding.get("status"))


def add_findings(profile_dir: Path, new: list[dict[str, Any]]) -> list[dict[str, Any]]:
    existing = load_findings(profile_dir)
    seen = {_key(finding) for finding in existing}
    for finding in new:
        key = _key(finding)
        if key in seen:
            continue
        seen.add(key)
        existing.append(finding)
    path = findings_path(profile_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    tmp.replace(path)
    return existing
