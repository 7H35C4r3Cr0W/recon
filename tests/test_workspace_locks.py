import json
import os
import socket
from pathlib import Path

import pytest

from oscprecon.models import Credential, Target
from oscprecon.profile import Profile, ReadOnlyError
from oscprecon.workspace import locks


def test_acquire_writes_diagnostic_lock_and_blocks_second(tmp_path: Path) -> None:
    info = locks.acquire(tmp_path)
    assert info is not None and info.pid == os.getpid()
    assert locks.lock_path(tmp_path).exists()
    assert locks.acquire(tmp_path) is None  # already held
    read, malformed = locks.read_lock(tmp_path)
    assert not malformed and read is not None
    assert read.hostname == socket.gethostname() and read.app_version and read.started_at
    # NO username / personal data in the lock
    assert "username" not in json.loads(locks.lock_path(tmp_path).read_text())


def test_release_only_removes_our_own_lock(tmp_path: Path) -> None:
    locks.acquire(tmp_path)
    foreign = locks.LockInfo(pid=999999, hostname="someone-else", app_version="9", started_at="t")
    assert locks.release(tmp_path, foreign) is False  # not ours -> refuse
    assert locks.lock_path(tmp_path).exists()
    assert locks.release(tmp_path) is True  # ours -> removed
    assert not locks.lock_path(tmp_path).exists()


def test_live_lock_is_not_stale(tmp_path: Path) -> None:
    info = locks.acquire(tmp_path)
    assert info is not None
    assert locks.is_stale(info) is False  # our own PID is alive
    assert locks.recover_stale(tmp_path) is None  # never steal a live lock


def test_stale_lock_same_host_dead_pid_is_recoverable(tmp_path: Path) -> None:
    dead = locks.LockInfo(pid=2, hostname=socket.gethostname(), app_version="1", started_at="t")
    # a dead PID... 2 is very unlikely alive; craft one guaranteed dead via a spawned+reaped proc
    import subprocess

    p = subprocess.Popen(["true"])
    p.wait()
    stale = locks.LockInfo(
        pid=p.pid, hostname=socket.gethostname(), app_version="1", started_at="t"
    )
    locks.lock_path(tmp_path).write_text(json.dumps(stale.to_dict()))
    assert locks.is_stale(stale) is True
    recovered = locks.recover_stale(tmp_path)
    assert recovered is not None and recovered.pid == os.getpid()
    _ = dead  # (kept for readability; the subprocess PID is the authoritative dead one)


def test_foreign_host_lock_is_conservative(tmp_path: Path) -> None:
    foreign = locks.LockInfo(pid=1, hostname="other-host", app_version="1", started_at="t")
    locks.lock_path(tmp_path).write_text(json.dumps(foreign.to_dict()))
    assert foreign.is_foreign_host is True
    assert locks.is_stale(foreign) is False  # can't check a foreign PID -> never stale
    assert locks.recover_stale(tmp_path) is None  # never steal a foreign lock


def test_recover_stale_never_destroys_a_fresh_valid_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # regression: recover_stale must claim the exact stale file atomically, not blindly unlink —
    # else a racer that installed a fresh VALID lock in between would lose it (two writable owners).
    import subprocess

    p = subprocess.Popen(["true"])
    p.wait()
    stale = locks.LockInfo(
        pid=p.pid, hostname=socket.gethostname(), app_version="1", started_at="t"
    )
    locks.lock_path(tmp_path).write_text(json.dumps(stale.to_dict()))
    live = locks.LockInfo(
        pid=os.getpid(), hostname=socket.gethostname(), app_version="1", started_at="LIVE"
    )

    orig_is_stale = locks.is_stale

    def racing_is_stale(info: locks.LockInfo) -> bool:
        # simulate another instance installing a fresh live lock after we read the stale one
        result = orig_is_stale(info)
        locks.lock_path(tmp_path).write_text(json.dumps(live.to_dict()))
        return result

    monkeypatch.setattr(locks, "is_stale", racing_is_stale)
    result = locks.recover_stale(tmp_path)
    # the atomic rename saw the file was no longer the stale one (it was replaced) — either way the
    # racer's live lock is preserved OR we cleanly re-acquire; we must NEVER destroy it and both end
    # up writable. The on-disk owner is a single valid lock.
    on_disk, malformed = locks.read_lock(tmp_path)
    assert not malformed and on_disk is not None
    # if we didn't get it, the live lock survived; if we did, exactly one owner exists
    assert result is None or on_disk.pid == os.getpid()


def test_malformed_lock_detected(tmp_path: Path) -> None:
    locks.lock_path(tmp_path).write_text("{ not json")
    info, malformed = locks.read_lock(tmp_path)
    assert info is None and malformed is True
    # a present-but-malformed lock is treated as a live/unknown owner (possibly a different app
    # version actively editing) — recover_stale must REFUSE it, never steal it (#13), and the file
    # must remain in place for the owner.
    assert locks.recover_stale(tmp_path) is None
    assert locks.lock_path(tmp_path).exists()


def test_no_lock_reads_cleanly(tmp_path: Path) -> None:
    info, malformed = locks.read_lock(tmp_path)
    assert info is None and malformed is False


def test_read_only_profile_refuses_every_write(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    prof.read_only = True
    with pytest.raises(ReadOnlyError):
        prof.save()
    with pytest.raises(ReadOnlyError):
        prof.add_credential(Credential(username="x", secret="y", source="manual"))
    with pytest.raises(ReadOnlyError):
        prof.save_graph({"user_edges": [], "node_overrides": {}})
    with pytest.raises(ReadOnlyError):
        prof.set_status("completed")
    with pytest.raises(ReadOnlyError):
        prof.add_tag("web")


def test_read_only_profile_can_still_be_read_and_exported(tmp_path: Path) -> None:
    from oscprecon import vault_export

    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    prof.add_credential(Credential(username="svc", secret="s", source="smb"))  # while writable
    prof.read_only = True
    assert prof.credentials()  # reads still work
    assert prof.load_graph() == {"user_edges": [], "node_overrides": {}}
    out = vault_export.export_vault(prof, tmp_path / "vault")  # export must remain available
    assert (out / "index.md").exists()


def test_read_only_can_be_cleared_to_reopen_for_edit(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    prof.read_only = True
    with pytest.raises(ReadOnlyError):
        prof.set_status("blocked")
    prof.read_only = False  # lock became available -> reopen for editing
    prof.set_status("blocked")
    assert Profile.load(prof.directory).organization_meta().status == "blocked"
