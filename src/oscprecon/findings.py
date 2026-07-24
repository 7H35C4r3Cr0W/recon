from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading
import uuid
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:  # Unix-only; the tool is Linux-first (§4). Absent on native Windows → cross-process lock is a
    import fcntl  # no-op there, and the in-process lock + per-pid tmp still prevent corruption.

    _HAVE_FCNTL = True
except ImportError:  # pragma: no cover
    _HAVE_FCNTL = False

# why: recon workers write findings from their own QThreads (bounded-parallel execution), and
# add_findings is a read-modify-write on findings.json — serialise it so concurrent writers can't
# clobber each other's appends. The atomic replace protects readers; this protects writers.
_WRITE_LOCK = threading.Lock()


@contextlib.contextmanager
def _cross_process_lock(path: Path) -> Iterator[None]:
    # a second GUI window opens a profile read-only (advisory .lock), but the CLI does not — so
    # `nabu-cli enum` and a GUI worker CAN write the same findings.json at once. An OS advisory lock
    # on a sidecar serialises the read-modify-write across processes so neither loses its appends.
    if not _HAVE_FCNTL:
        yield
        return
    lock_path = path.with_name(path.name + ".lock")
    with open(lock_path, "w", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


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


def _write_atomic(path: Path, items: list[dict[str, Any]]) -> None:
    # a per-process unique tmp (not a fixed <name>.tmp): two processes writing the shared fixed
    # tmp interleaved their bytes and left a corrupt file behind the atomic replace.
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(items, indent=2))
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def add_findings(profile_dir: Path, new: list[dict[str, Any]]) -> list[dict[str, Any]]:
    path = findings_path(profile_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _WRITE_LOCK, _cross_process_lock(path):  # in-process AND cross-process serialisation
        existing = load_findings(profile_dir)
        seen = {_key(finding) for finding in existing}
        for finding in new:
            key = _key(finding)
            if key in seen:
                continue
            seen.add(key)
            existing.append(finding)
        _write_atomic(path, existing)
        return existing


# --- operator-entered findings ------------------------------------------------------------------
# What a parser can't see: the thing YOU found (a working SQLi, a credential in a PDF, the box's
# actual foothold). Stored in the same findings.json as parsed findings — so they flow into the
# Findings view, the graph and report.md — but marked `manual: true` and carrying an id, so they
# stay editable/deletable and are never confused with tool output.
MANUAL_MODULE = "manual"


def new_finding_id() -> str:
    return uuid.uuid4().hex[:12]


def add_manual_finding(profile_dir: Path, finding: dict[str, Any]) -> dict[str, Any]:
    path = findings_path(profile_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    entry: dict[str, Any] = {
        "module": str(finding.get("module") or MANUAL_MODULE),
        **{k: v for k, v in finding.items() if k != "module"},
        "manual": True,
        "id": str(finding.get("id") or new_finding_id()),
        "added_at": str(finding.get("added_at") or _now()),
    }
    with _WRITE_LOCK, _cross_process_lock(path):
        existing = load_findings(profile_dir)
        existing.append(entry)  # never deduped: two hand-written notes may legitimately match
        _write_atomic(path, existing)
    return entry


def update_manual_finding(profile_dir: Path, finding_id: str, updates: dict[str, Any]) -> bool:
    path = findings_path(profile_dir)
    if not finding_id:
        return False
    with _WRITE_LOCK, _cross_process_lock(path):
        existing = load_findings(profile_dir)
        for index, item in enumerate(existing):
            if item.get("id") != finding_id or not item.get("manual"):
                continue
            merged = {**item, **updates}
            merged["id"] = finding_id  # identity is never rewritten by an edit
            merged["manual"] = True
            existing[index] = merged
            _write_atomic(path, existing)
            return True
    return False


def delete_manual_finding(profile_dir: Path, finding_id: str) -> bool:
    # only operator-entered findings are deletable — parsed tool output stays the record of what
    # the tools actually saw.
    path = findings_path(profile_dir)
    if not finding_id:
        return False
    with _WRITE_LOCK, _cross_process_lock(path):
        existing = load_findings(profile_dir)
        kept = [f for f in existing if not (f.get("id") == finding_id and f.get("manual"))]
        if len(kept) == len(existing):
            return False
        _write_atomic(path, kept)
        return True


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
