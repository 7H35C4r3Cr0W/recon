from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path


def lock_path(directory: Path) -> Path:
    return Path(directory) / ".lock"


def _app_version() -> str:
    try:
        return metadata.version("oscp-recon")
    except metadata.PackageNotFoundError:
        return "0.0.1"


@dataclass
class LockInfo:
    pid: int
    hostname: str
    app_version: str
    started_at: str

    def to_dict(self) -> dict[str, object]:
        # deliberately NO username or other personal data — just enough to identify the owner.
        return {
            "pid": self.pid,
            "hostname": self.hostname,
            "app_version": self.app_version,
            "started_at": self.started_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> LockInfo:
        pid_raw = data.get("pid", 0)
        pid = int(pid_raw) if isinstance(pid_raw, int | str) else 0
        return cls(
            pid=pid,
            hostname=str(data.get("hostname", "")),
            app_version=str(data.get("app_version", "")),
            started_at=str(data.get("started_at", "")),
        )

    @property
    def is_foreign_host(self) -> bool:
        return bool(self.hostname) and self.hostname != socket.gethostname()


def current_lock_info() -> LockInfo:
    return LockInfo(
        pid=os.getpid(),
        hostname=socket.gethostname(),
        app_version=_app_version(),
        started_at=datetime.now(UTC).isoformat(),
    )


def read_lock(directory: Path) -> tuple[LockInfo | None, bool]:
    """(info, malformed). (None, False) = no lock; (None, True) = present but unreadable;
    (info, False) = a valid lock."""
    path = lock_path(directory)
    if not path.exists():
        return None, False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError, UnicodeError):
        return None, True
    if not isinstance(data, dict) or "pid" not in data:
        return None, True
    try:
        return LockInfo.from_dict(data), False
    except (ValueError, TypeError):
        return None, True


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but owned by another user
    except OSError:
        return False
    return True


def is_stale(info: LockInfo) -> bool:
    # ONLY same-host + provably-dead PID is stale. A live PID (possibly reused) or a foreign host is
    # treated conservatively as live and is never auto-recovered.
    if info.is_foreign_host:
        return False
    return not _pid_alive(info.pid)


def acquire(directory: Path) -> LockInfo | None:
    """Atomically create <profile>/.lock. Returns our LockInfo on success, None if already held."""
    path = lock_path(directory)
    info = current_lock_info()
    payload = json.dumps(info.to_dict(), indent=2).encode("utf-8")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
        return None
    except OSError:
        return None
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    return info


def release(directory: Path, info: LockInfo | None = None) -> bool:
    """Remove the lock only if it is ours (pid + host match) or the caller passes our info."""
    existing, malformed = read_lock(directory)
    if existing is None and not malformed:
        return False  # nothing to release
    owner = info or current_lock_info()
    if (
        existing is not None
        and not malformed
        and (existing.pid != owner.pid or existing.hostname != owner.hostname)
    ):
        return False  # not ours — never release someone else's lock
    try:
        lock_path(directory).unlink(missing_ok=True)
    except OSError:
        return False
    return True


def recover_stale(directory: Path) -> LockInfo | None:
    """If the current lock is provably stale (same host, dead PID) or malformed, replace it and
    acquire a fresh one. Never steals a live or foreign-host lock (returns None)."""
    existing, malformed = read_lock(directory)
    if existing is not None and not is_stale(existing):
        return None  # live or foreign — refuse
    try:
        lock_path(directory).unlink(missing_ok=True)
    except OSError:
        return None
    return acquire(directory)
