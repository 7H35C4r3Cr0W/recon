from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading
from collections.abc import Iterator
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
        # a per-process unique tmp (not a fixed <name>.tmp): two processes writing the shared fixed
        # tmp interleaved their bytes and left a corrupt file behind the atomic replace.
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(existing, indent=2))
            os.replace(tmp_name, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise
        return existing
