from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

# why: recon workers write findings from their own QThreads (bounded-parallel execution), and
# add_findings is a read-modify-write on findings.json — serialise it so concurrent writers can't
# clobber each other's appends. The atomic replace protects readers; this protects writers.
_WRITE_LOCK = threading.Lock()


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


def _key(finding: dict[str, Any]) -> tuple[Any, ...]:
    # why: two findings that share path+status but differ in size/redirect/note are distinct
    # (e.g. wpscan's version vs users entries are both ('http',80,'/',0)) — don't collapse them.
    return (
        finding.get("module"),
        finding.get("port"),
        finding.get("path"),
        finding.get("vhost"),
        finding.get("kind"),
        finding.get("value"),
        finding.get("status"),
        finding.get("size"),
        finding.get("redirect_to"),
        finding.get("note"),
        finding.get(
            "detail"
        ),  # policy/peek findings differ only here (e.g. 'threshold: 5' vs 'duration: 30m')
    )


def add_findings(profile_dir: Path, new: list[dict[str, Any]]) -> list[dict[str, Any]]:
    with _WRITE_LOCK:
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
