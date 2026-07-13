import os
import stat
from pathlib import Path

import pytest

from oscprecon import findings as findings_mod
from oscprecon.models import Credential, DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.workspace import health


def _codes(directory: Path, **kw: object) -> set[str]:
    return {i.code for i in health.check_profile(directory, **kw)}  # type: ignore[arg-type]


def test_healthy_profile_has_no_errors(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    prof.add_credential(Credential(username="x", secret="y", source="smb"))
    issues = health.check_profile(prof.directory, workspace_root=tmp_path)
    assert not [i for i in issues if i.severity == "error"]


def test_missing_and_corrupt_profile_json(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    prof.profile_json_path.write_text("{ truncated")
    assert "corrupt-profile-json" in _codes(prof.directory)
    prof.profile_json_path.unlink()
    assert "missing-profile-json" in _codes(prof.directory)


def test_corrupt_findings_and_creds_and_graph(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    (prof.directory / "findings.json").write_text("]]")
    (prof.directory / "creds.json").write_text("{bad")
    (prof.directory / "graph.json").write_text("nope")
    codes = _codes(prof.directory)
    assert {"corrupt-findings.json", "corrupt-creds.json", "corrupt-graph.json"} <= codes


def test_stale_temp_and_missing_output_and_orphan_findings(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    prof.set_services([DiscoveredService(80, Proto.TCP, "http")])
    prof.add_command({"id": "c1", "output_file": "nmap/gone.txt", "exit_code": 0})
    prof.save()
    findings_mod.add_findings(
        prof.directory, [{"module": "x", "kind": "y", "value": "z", "port": 9999}]
    )
    (prof.directory / "leftover.tmp").write_text("interrupted")
    codes = _codes(prof.directory)
    assert "stale-temp-files" in codes
    assert "missing-output-files" in codes
    assert "orphan-findings" in codes


def test_malformed_audit_lines_counted(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    (prof.directory / "audit.jsonl").write_text('{"ok": 1}\nGARBAGE LINE\n{"ok": 2}\n')
    assert "malformed-audit-lines" in _codes(prof.directory)


def test_path_escape_flagged(tmp_path: Path) -> None:
    other = tmp_path / "outside"
    prof = Profile.create(other, "b", Target(ip="10.0.0.1"))
    workspace = tmp_path / "ws"
    workspace.mkdir()
    assert "path-escape" in _codes(prof.directory, workspace_root=workspace)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")
def test_world_readable_creds_flagged_and_repaired(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    prof.add_credential(Credential(username="x", secret="y", source="smb"))
    os.chmod(prof.creds_path, 0o644)  # loosen the permissions
    assert "creds-permissions" in _codes(prof.directory)
    assert health.repair_creds_permissions(prof.directory) is True
    assert stat.S_IMODE(prof.creds_path.stat().st_mode) == 0o600
    assert "creds-permissions" not in _codes(prof.directory)


def test_repair_stale_temp_backs_up_not_deletes(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    (prof.directory / "a.tmp").write_text("interrupted-A")
    (prof.directory / "b.tmp").write_text("interrupted-B")
    moved = health.repair_remove_stale_temp(prof.directory)
    assert set(moved) == {"a.tmp", "b.tmp"}
    assert not list(prof.directory.glob("*.tmp"))  # gone from the profile root
    backups = list((prof.directory / "health-backup").rglob("*.tmp"))
    assert {p.name for p in backups} == {"a.tmp", "b.tmp"}  # preserved, not deleted
    assert any(p.read_text() == "interrupted-A" for p in backups)


def test_health_is_read_only(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    before = prof.profile_json_path.read_bytes()
    health.check_profile(prof.directory, workspace_root=tmp_path)
    assert prof.profile_json_path.read_bytes() == before  # unchanged
