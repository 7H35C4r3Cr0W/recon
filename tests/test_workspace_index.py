import os
from pathlib import Path

import pytest

from oscprecon import findings as findings_mod
from oscprecon.models import Credential, DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.workspace import scan_workspace, summarize_profile


def _valid(root: Path, name: str, ip: str = "10.0.0.1") -> Profile:
    return Profile.create(root, name, Target(ip=ip, platform="htb"))


def test_scan_discovers_valid_profiles_and_ignores_unrelated(tmp_path: Path) -> None:
    _valid(tmp_path, "alpha")
    _valid(tmp_path, "beta")
    (tmp_path / "not-a-profile").mkdir()  # empty folder -> ignored
    (tmp_path / "random").mkdir()
    (tmp_path / "random" / "notes.txt").write_text("hi")  # no profile.json -> ignored
    (tmp_path / "loose-file.txt").write_text("x")  # a file -> ignored
    names = {s.name for s in scan_workspace(tmp_path)}
    assert names == {"alpha", "beta"}


def test_summary_counts_are_lightweight_and_correct(tmp_path: Path) -> None:
    prof = _valid(tmp_path, "box")
    prof.set_services([DiscoveredService(80, Proto.TCP, "http"), DiscoveredService(445, Proto.TCP)])
    prof.add_command({"id": "c1", "exit_code": 0})
    prof.add_command({"id": "c2", "exit_code": 1})
    prof.add_command({"id": "c3", "exit_code": -9})  # cancelled
    prof.save()
    findings_mod.add_findings(prof.directory, [{"module": "http", "kind": "path", "value": "/x"}])
    prof.add_credential(Credential(username="svc", secret="s3cr3t", source="smb-anon-enum"))
    prof.notes_path.write_text("# box — notes\n\nfound GPP creds\n")

    s = summarize_profile(prof.directory)
    assert s.service_count == 2
    assert s.commands_completed == 1 and s.commands_failed == 2
    assert s.finding_count == 1 and s.credential_count == 1
    assert s.platform == "htb" and s.has_notes and not s.has_report and not s.has_graph
    assert not s.corrupt and s.warnings == []


def test_corrupt_profile_is_surfaced_not_hidden(tmp_path: Path) -> None:
    prof = _valid(tmp_path, "broken")
    prof.profile_json_path.write_text("{ this is not json")
    s = summarize_profile(prof.directory)
    assert s.corrupt and any("corrupt profile.json" in w for w in s.warnings)
    assert "broken" in {x.name for x in scan_workspace(tmp_path)}  # still listed


def test_partial_profile_interrupted_create(tmp_path: Path) -> None:
    d = tmp_path / "partial"
    d.mkdir()
    (d / "profile.json.tmp").write_text('{"profile_name": "partial"}')  # crash mid-create
    summaries = scan_workspace(tmp_path)
    assert [s.name for s in summaries] == ["partial"]
    assert summaries[0].corrupt and any("interrupted create" in w for w in summaries[0].warnings)


def test_corrupt_findings_and_creds_flagged_but_profile_still_read(tmp_path: Path) -> None:
    prof = _valid(tmp_path, "box")
    (prof.directory / "findings.json").write_text("]]not json[[")
    (prof.directory / "creds.json").write_text("{bad")
    s = summarize_profile(prof.directory)
    assert not s.corrupt  # profile.json itself is fine
    assert s.target.startswith("10.0.0.1")
    assert any("corrupt findings.json" in w for w in s.warnings)
    assert any("corrupt creds.json" in w for w in s.warnings)


def test_symlink_escaping_workspace_is_skipped(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    _valid(workspace, "real")
    outside = tmp_path / "outside"
    _valid(outside, "secret-elsewhere")
    (workspace / "sneaky").symlink_to(outside, target_is_directory=True)  # escape attempt
    names = {s.name for s in scan_workspace(workspace)}
    assert names == {"real"}  # the escaping symlink is not followed


def test_missing_optional_files_default_to_absent(tmp_path: Path) -> None:
    prof = _valid(tmp_path, "bare")
    s = summarize_profile(prof.directory)
    assert not s.has_notes and not s.has_report and not s.has_graph
    assert s.finding_count == 0 and s.credential_count == 0


def test_pinned_and_archived_sort_and_filter(tmp_path: Path) -> None:
    _valid(tmp_path, "a")
    b = _valid(tmp_path, "b")
    c = _valid(tmp_path, "c")
    b.set_pinned(True)
    c.set_archived(True)
    ordered = scan_workspace(tmp_path)
    assert ordered[0].name == "b"  # pinned first
    assert ordered[-1].name == "c"  # archived last
    assert {s.name for s in scan_workspace(tmp_path, include_archived=False)} == {"a", "b"}


def test_symlinked_profile_json_escaping_root_is_not_read(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    outside = tmp_path / "outside"
    secret = Profile.create(outside, "secret", Target(ip="9.9.9.9", hostname="secretbox"))
    # a REAL dir under the workspace whose profile.json is a symlink to an out-of-root file
    pwn = workspace / "pwn"
    pwn.mkdir()
    (pwn / "profile.json").symlink_to(secret.profile_json_path)
    summaries = scan_workspace(workspace)
    row = next(s for s in summaries if s.name == "pwn")
    assert row.corrupt and any("symlinks outside" in w for w in row.warnings)
    assert "9.9.9.9" not in row.target  # the out-of-root file's contents were NOT read


def test_scan_is_cancellable(tmp_path: Path) -> None:
    import threading

    _valid(tmp_path, "a")
    _valid(tmp_path, "b")
    cancel = threading.Event()
    cancel.set()  # cancelled before the loop starts
    assert scan_workspace(tmp_path, cancel=cancel) == []  # cooperative cancel -> nothing scanned


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses permission bits")
def test_unreadable_profile_does_not_crash_scan(tmp_path: Path) -> None:
    prof = _valid(tmp_path, "locked-perms")
    _valid(tmp_path, "readable")
    prof.profile_json_path.chmod(0o000)
    try:
        summaries = scan_workspace(tmp_path)
        assert "readable" in {s.name for s in summaries}
        broken = next(s for s in summaries if s.name == "locked-perms")
        assert broken.corrupt  # permission failure -> corrupt/warning row, not a crash
    finally:
        prof.profile_json_path.chmod(0o644)
