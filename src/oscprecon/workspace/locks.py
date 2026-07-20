from __future__ import annotations

import contextlib
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


def is_ours(info: LockInfo) -> bool:
    # a lock is "ours" ONLY if it matches this process ON THIS HOST. A PID-only check mis-treats a
    # foreign-host lock whose PID coincidentally equals ours as ours (is_stale() returns False for a
    # foreign host), letting us mutate/delete a profile a live instance on another host still holds.
    return info.pid == os.getpid() and info.hostname == socket.gethostname()


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
    """Remove the lock only if it is ours (pid + host match). A malformed lock is never unlinked —
    we can't prove we own it, and it may belong to a live instance of a different app version."""
    existing, malformed = read_lock(directory)
    if existing is None:
        return False  # no readable lock (absent, or malformed = not provably ours) — leave it
    owner = info or current_lock_info()
    if existing.pid != owner.pid or existing.hostname != owner.hostname:
        return False  # not ours — never release someone else's lock
    try:
        lock_path(directory).unlink(missing_ok=True)
    except OSError:
        return False
    return True


def _sweep_stale_orphans(directory: Path) -> None:
    # remove leftover .lock.stale.<pid> rename-artifacts from crashed recoveries so they never
    # linger or travel in an export. Only clear one whose pid is provably dead, so we don't race an
    # in-flight recovery that is between os.rename and claimed.unlink.
    for orphan in Path(directory).glob(".lock.stale.*"):
        suffix = orphan.name.rsplit(".", 1)[-1]
        try:
            pid = int(suffix)
        except ValueError:
            pid = 0
        if not _pid_alive(pid):
            with contextlib.suppress(OSError):
                orphan.unlink()


def recover_stale(directory: Path) -> LockInfo | None:
    """If the current lock is provably stale (same host, dead PID), replace it and acquire a fresh
    one. Refuses (returns None) a live lock, a foreign-host lock, OR a present-but-malformed lock:
    an unreadable lock is an unknown/other-version owner we cannot prove dead, so we never steal it.

    The claim is atomic: only the instance that wins an os.rename of the exact stale file removes
    it, so two instances racing to recover the same stale lock can never both end up writable (the
    loser's rename fails, and acquire() is O_EXCL so at most one gets the fresh lock)."""
    _sweep_stale_orphans(directory)
    existing, malformed = read_lock(directory)
    if malformed:
        return None  # present but unparseable — treat as a live/unknown owner, never reclaim
    if existing is None:
        return acquire(directory)  # genuinely no lock (or already cleared) — take it directly
    if not is_stale(existing):
        return None  # live or foreign — refuse
    path = lock_path(directory)
    claimed = path.with_name(f".lock.stale.{os.getpid()}")
    try:
        os.rename(path, claimed)  # atomic: exactly one racer wins; the file we inspected is gone
    except FileNotFoundError:
        pass  # another instance already cleared it — fall through to a clean acquire
    except OSError:
        return None
    else:
        with contextlib.suppress(OSError):
            claimed.unlink(missing_ok=True)
    return acquire(directory)  # O_EXCL — only one instance can win this
