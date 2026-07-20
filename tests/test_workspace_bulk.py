import threading
from pathlib import Path

from oscprecon.models import Target
from oscprecon.profile import Profile
from oscprecon.workspace import bulk, locks


def _profiles(root: Path, *names: str) -> list[Profile]:
    return [Profile.create(root, n, Target(ip=f"10.0.0.{i + 1}")) for i, n in enumerate(names)]


def test_bulk_add_tag_and_status_across_profiles(tmp_path: Path) -> None:
    profs = _profiles(tmp_path, "a", "b", "c")
    dirs = [p.directory for p in profs]
    results = bulk.run_bulk(dirs, bulk.add_tag("web"))
    assert all(r.ok for r in results) and len(results) == 3
    assert all("web" in Profile.load(p.directory).organization_meta().tags for p in profs)
    bulk.run_bulk(dirs, bulk.set_status("completed"))
    assert all(Profile.load(p.directory).organization_meta().status == "completed" for p in profs)


def test_bulk_archive_and_restore(tmp_path: Path) -> None:
    profs = _profiles(tmp_path, "a", "b")
    dirs = [p.directory for p in profs]
    bulk.run_bulk(dirs, bulk.set_archived(True))
    assert all(Profile.load(p.directory).organization_meta().archived for p in profs)
    bulk.run_bulk(dirs, bulk.set_archived(False))
    assert not any(Profile.load(p.directory).organization_meta().archived for p in profs)


def test_bulk_skips_corrupt_and_continues(tmp_path: Path) -> None:
    a, b, c = _profiles(tmp_path, "a", "b", "c")
    b.profile_json_path.write_text("{ corrupt")  # middle profile broken
    results = bulk.run_bulk([a.directory, b.directory, c.directory], bulk.add_tag("x"))
    by_name = {r.profile: r for r in results}
    assert by_name["a"].ok and by_name["c"].ok  # the batch did NOT stop at the failure
    assert not by_name["b"].ok and "corrupt" in by_name["b"].message


def test_bulk_skips_profile_locked_by_another_instance(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    a, b = _profiles(tmp_path, "a", "b")
    # simulate a live lock owned by a different, alive PID (this test process's parent)
    import os

    other = locks.LockInfo(
        pid=os.getppid(),
        hostname=__import__("socket").gethostname(),
        app_version="1",
        started_at="t",
    )
    import json

    locks.lock_path(b.directory).write_text(json.dumps(other.to_dict()))
    monkeypatch.setattr(locks, "is_stale", lambda info: False)  # force "live"
    results = bulk.run_bulk([a.directory, b.directory], bulk.add_tag("x"))
    by_name = {r.profile: r for r in results}
    assert by_name["a"].ok
    assert not by_name["b"].ok and "locked" in by_name["b"].message
    assert "x" not in Profile.load(b.directory).organization_meta().tags  # untouched


def test_bulk_skips_profile_with_malformed_lock(tmp_path: Path) -> None:
    # a present-but-unreadable .lock is a live/unknown owner the rest of the system refuses to touch
    # (locks.recover_stale/release) — run_bulk must skip it too, never clobber the profile under it.
    a, b = _profiles(tmp_path, "a", "b")
    locks.lock_path(b.directory).write_text("{ not valid json ")
    results = bulk.run_bulk([a.directory, b.directory], bulk.add_tag("x"))
    by_name = {r.profile: r for r in results}
    assert by_name["a"].ok
    assert not by_name["b"].ok and "locked" in by_name["b"].message
    assert "x" not in Profile.load(b.directory).organization_meta().tags  # untouched


def test_bulk_cancellation_marks_remaining(tmp_path: Path) -> None:
    profs = _profiles(tmp_path, "a", "b", "c")
    cancel = threading.Event()
    cancel.set()  # cancelled before we start
    results = bulk.run_bulk([p.directory for p in profs], bulk.add_tag("x"), cancel=cancel)
    assert all(not r.ok and r.message == "cancelled" for r in results)


def test_bulk_health_and_report(tmp_path: Path) -> None:
    profs = _profiles(tmp_path, "a", "b")
    dirs = [p.directory for p in profs]
    health_results = bulk.run_bulk(dirs, bulk.health_check())
    assert all(r.ok for r in health_results)  # fresh profiles are healthy
    report_results = bulk.run_bulk(dirs, bulk.generate_report())
    assert all(r.ok for r in report_results)
    assert all((p.directory / "report.md").exists() for p in profs)


def test_bulk_op_exception_is_isolated(tmp_path: Path) -> None:
    profs = _profiles(tmp_path, "a", "b")

    def boom(profile: Profile) -> tuple[bool, str]:
        if profile.profile_name == "a":
            raise RuntimeError("kaboom")
        return True, "ok"

    results = bulk.run_bulk([p.directory for p in profs], boom)
    by_name = {r.profile: r for r in results}
    assert not by_name["a"].ok and "kaboom" in by_name["a"].message
    assert by_name["b"].ok  # b still processed after a's exception
