from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import oscprecon.cli as cli_mod
from oscprecon.audit import load_entries
from oscprecon.cli import app
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile

runner = CliRunner()

NSE_FIXTURE = Path(__file__).parent / "fixtures" / "nse" / "smb-vuln-showall.txt"


def _actions(directory: Path) -> list[str]:
    return [str(entry.get("action", "")) for entry in load_entries(directory)]


def _details(directory: Path, action: str) -> dict[str, Any]:
    for entry in load_entries(directory):
        if entry.get("action") == action:
            found = entry.get("details")
            return found if isinstance(found, dict) else {}
    return {}


def _stub_shell(monkeypatch: pytest.MonkeyPatch, text: str = "") -> None:
    class Result:
        missing_tool = None
        blocked = None
        exit_code = 0

    def fake_run(command: str, output_file: Path, **_kw: Any) -> Result:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(text, encoding="utf-8")
        return Result()

    monkeypatch.setattr(cli_mod.shell, "run", fake_run)


def _box(tmp_path: Path, name: str = "box") -> Profile:
    profile = Profile.create(tmp_path, name, Target(ip="10.10.10.100"))
    profile.set_services(
        [
            DiscoveredService(port=445, proto=Proto.TCP, service="microsoft-ds", discovered_at=""),
        ]
    )
    profile.save()
    return profile


def test_scan_records_the_run_in_the_audit_trail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # §6a wants a COMPLETE exam trail — headless work must land in audit.jsonl exactly like GUI
    # work, under the SAME slugs, or `activity` tells a half-story.
    class FakeOrch:
        def __init__(self, _profile: Any, **_kw: Any) -> None:
            pass

        def run_nmap(self) -> None:
            pass

    monkeypatch.setattr(cli_mod, "Orchestrator", FakeOrch)
    result = runner.invoke(app, ["scan", "10.10.10.5", "-p", "box", "--workspace", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert _actions(tmp_path / "box") == ["profile-created", "run", "run-finished"]
    assert _details(tmp_path / "box", "run")["label"] == "scan:10.10.10.5"


def test_activity_shows_what_a_headless_scan_did(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the deliverable is the timeline the operator reads, not the file — go through `activity`.
    class FakeOrch:
        def __init__(self, _profile: Any, **_kw: Any) -> None:
            pass

        def run_nmap(self) -> None:
            pass

    monkeypatch.setattr(cli_mod, "Orchestrator", FakeOrch)
    runner.invoke(app, ["scan", "10.10.10.5", "-p", "box", "--workspace", str(tmp_path)])
    result = runner.invoke(app, ["activity", "-p", "box", "--workspace", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Profile created" in result.output
    assert "Scan started" in result.output and "Scan finished" in result.output


def test_a_scan_that_fails_still_records_the_end_of_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the GUI audits run-finished from the worker's `finished` signal, i.e. on failure too. A trail
    # with a start and no end reads as "still running" hours later.
    class BoomOrch:
        def __init__(self, _profile: Any, **_kw: Any) -> None:
            pass

        def run_nmap(self) -> None:
            raise RuntimeError("nmap exploded")

    monkeypatch.setattr(cli_mod, "Orchestrator", BoomOrch)
    runner.invoke(app, ["scan", "10.10.10.5", "-p", "box", "--workspace", str(tmp_path)])
    assert _actions(tmp_path / "box")[-1] == "run-finished"


def test_enum_records_a_run_for_the_service_it_enumerated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    Profile.create(tmp_path, "box", Target(ip="10.10.10.100")).save()
    _stub_shell(monkeypatch)
    result = runner.invoke(app, ["enum", "mssql", "-p", "box", "--workspace", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert _actions(tmp_path / "box") == ["run", "run-finished"]
    assert _details(tmp_path / "box", "run")["module"] == "mssql"


def test_vuln_records_the_same_vuln_scan_event_the_gui_does(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # slug parity matters: the GUI writes "vuln-scan" with service/port/mode, so a mixed
    # GUI + CLI session must produce ONE readable timeline, not two incompatible ones.
    _box(tmp_path)
    _stub_shell(monkeypatch, NSE_FIXTURE.read_text(encoding="utf-8"))
    result = runner.invoke(app, ["vuln", "smb", "-p", "box", "--workspace", str(tmp_path)])
    assert result.exit_code == 0, result.output
    actions = _actions(tmp_path / "box")
    assert actions == ["run", "vuln-scan", "run-finished"]
    details = _details(tmp_path / "box", "vuln-scan")
    assert details["service"] == "smb" and details["mode"] == "vuln"
    assert details["host"] == "10.10.10.100" and details["port"] == 445


def test_creds_and_findings_changes_are_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _box(tmp_path)
    creds_argv = ["creds", "add", "-p", "box", "-u", "svc", "-s", "Passw0rd!"]
    runner.invoke(app, [*creds_argv, "--workspace", str(tmp_path)])
    runner.invoke(app, ["add-finding", "-p", "box", "SQLi in /q.php", "--workspace", str(tmp_path)])
    assert _actions(tmp_path / "box") == ["credential-added", "finding-added"]
    # §6a logs the field names + source of a credential, never the secret itself
    stored = (tmp_path / "box" / "audit.jsonl").read_text(encoding="utf-8")
    assert "svc" in stored and "Passw0rd!" not in stored


@pytest.mark.parametrize(
    "argv",
    [
        ["list"],
        ["findings", "-p", "box"],
        ["activity", "-p", "box"],
        ["health", "-p", "box"],
        ["exploit", "smb", "-p", "box"],
    ],
)
def test_a_read_only_command_writes_no_audit_entries(
    tmp_path: Path, argv: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # reads are not project history — auditing them would bury the real work under noise.
    _box(tmp_path)
    result = runner.invoke(app, [*argv, "--workspace", str(tmp_path)])
    assert result.exit_code in (0, 1), result.output
    assert not (tmp_path / "box" / "audit.jsonl").exists()


def test_an_unwritable_audit_log_does_not_break_the_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # §6a: audit writes are best-effort. A directory where audit.jsonl belongs makes every append
    # fail — `enum` must still run, parse and report, because the recon is the point, not the log.
    Profile.create(tmp_path, "box", Target(ip="10.10.10.100")).save()
    (tmp_path / "box" / "audit.jsonl").mkdir()
    _stub_shell(monkeypatch)
    result = runner.invoke(app, ["enum", "mssql", "-p", "box", "--workspace", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "[enum] mssql:" in result.output
    assert load_entries(tmp_path / "box") == []
