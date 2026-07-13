from pathlib import Path

from oscprecon.audit import Auditor, audit_path
from oscprecon.models import Target
from oscprecon.profile import Profile
from oscprecon.workspace import activity


def _seed_audit(prof: Profile) -> Auditor:
    auditor = Auditor(prof.directory, prof.profile_name)
    auditor.record("profile-created", details={"target": "10.0.0.1"})
    auditor.record("run", details={"label": "smb full"})
    auditor.record("credential-added", details={"username": "svc", "source": "smb-anon-enum"})
    return auditor


def test_activity_is_human_readable_newest_first(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    _seed_audit(prof)
    events, malformed = activity.load_activity(prof.directory)
    assert malformed == 0
    descriptions = [e.description for e in events]
    assert any("Credential added" in d for d in descriptions)
    assert any("Scan started" in d and "smb full" in d for d in descriptions)
    assert events[0].event_type == "credential-added"  # newest first
    assert all(e.date and len(e.date) == 10 for e in events)  # YYYY-MM-DD grouping key


def test_malformed_audit_line_skipped_and_counted(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    _seed_audit(prof)
    with audit_path(prof.directory).open("a", encoding="utf-8") as fh:
        fh.write("THIS IS NOT JSON\n")
        fh.write('{"ts": "2026-07-13T10:00:00", "action": "profile-saved", "profile": "b"}\n')
    events, malformed = activity.load_activity(prof.directory)
    assert malformed == 1  # the garbage line counted, not fatal
    assert any(e.event_type == "profile-saved" for e in events)  # the rest still parsed


def test_activity_never_shows_secret_values(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    auditor = Auditor(prof.directory, prof.profile_name)
    # even if a caller tries to log a secret, the auditor redacts + activity only shows safe keys
    auditor.record("credential-added", details={"username": "svc", "secret": "P@ssw0rd!"})
    events, _ = activity.load_activity(prof.directory)
    assert not any("P@ssw0rd" in e.description for e in events)
    assert any("username=svc" in e.description for e in events)


def test_workspace_activity_aggregates_and_filters(tmp_path: Path) -> None:
    a = Profile.create(tmp_path, "a", Target(ip="10.0.0.1"))
    b = Profile.create(tmp_path, "b", Target(ip="10.0.0.2"))
    Auditor(a.directory, "a").record("run", details={"label": "x"})
    Auditor(b.directory, "b").record("profile-saved")
    events, _ = activity.load_workspace_activity(tmp_path)
    assert {e.profile for e in events} >= {"a", "b"}
    by_type, _ = activity.load_workspace_activity(tmp_path, event_types=["run"])
    assert all(e.event_type == "run" for e in by_type)
    by_profile, _ = activity.load_workspace_activity(tmp_path, profiles=["a"])
    assert {e.profile for e in by_profile} == {"a"}


def test_empty_and_missing_audit(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    events, malformed = activity.load_activity(prof.directory)
    assert events == [] and malformed == 0  # a fresh profile has no audit yet
