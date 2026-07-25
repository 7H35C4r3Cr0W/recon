from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import oscprecon.cli as cli_mod
from oscprecon.cli import app
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile

runner = CliRunner()

FIXTURE = Path(__file__).parent / "fixtures" / "nse" / "smb-vuln-showall.txt"


def _box(tmp_path: Path) -> Profile:
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.100"))
    profile.set_services(
        [
            DiscoveredService(port=139, proto=Proto.TCP, service="netbios-ssn", discovered_at=""),
            DiscoveredService(port=445, proto=Proto.TCP, service="microsoft-ds", discovered_at=""),
            DiscoveredService(
                port=3389, proto=Proto.TCP, service="ms-wbt-server", discovered_at=""
            ),
        ]
    )
    profile.save()
    return profile


def _stub_shell(monkeypatch: pytest.MonkeyPatch, text: str) -> list[str]:
    """Capture the commands the CLI would run, and hand back canned nmap output."""
    commands: list[str] = []

    class Result:
        missing_tool = None
        blocked = None
        exit_code = 0

    def fake_run(command: str, output_file: Path, **_kw: Any) -> Result:
        commands.append(command)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(text, encoding="utf-8")
        return Result()

    monkeypatch.setattr(cli_mod.shell, "run", fake_run)
    return commands


def test_no_arg_lists_what_each_discovered_service_maps_to(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _box(tmp_path)
    result = runner.invoke(app, ["vuln", "-p", "box", "--workspace", str(tmp_path)])
    assert result.exit_code == 0
    assert "SMB / NetBIOS" in result.output
    assert "RDP" in result.output
    assert "139,445" in result.output  # one grouped entry, not two per-port ones


def test_a_service_family_is_scanned_once_for_all_its_ports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _box(tmp_path)
    commands = _stub_shell(monkeypatch, FIXTURE.read_text(encoding="utf-8"))
    result = runner.invoke(app, ["vuln", "smb", "-p", "box", "--workspace", str(tmp_path)])
    assert result.exit_code == 0
    assert len(commands) == 1  # 139 + 445 are ONE nmap pass
    assert "-p 139,445" in commands[0]


def test_the_service_can_be_named_by_key_or_by_the_nmap_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _box(tmp_path)
    for name in ("smb", "microsoft-ds"):
        commands = _stub_shell(monkeypatch, FIXTURE.read_text(encoding="utf-8"))
        result = runner.invoke(app, ["vuln", name, "-p", "box", "--workspace", str(tmp_path)])
        assert result.exit_code == 0, name
        assert commands, name


def test_a_confirmed_verdict_is_reported_and_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from oscprecon import findings as findings_mod

    profile = _box(tmp_path)
    _stub_shell(monkeypatch, FIXTURE.read_text(encoding="utf-8"))
    result = runner.invoke(app, ["vuln", "smb", "-p", "box", "--workspace", str(tmp_path)])
    assert result.exit_code == 0
    assert "VULNERABLE: smb-vuln-ms17-010" in result.output
    assert "could not check" in result.output  # an unreached verdict is stated, not swallowed
    rows = findings_mod.load_findings(profile.directory)
    confirmed = [r for r in rows if r.get("kind") == "vuln"]
    assert [r["value"] for r in confirmed] == ["smb-vuln-ms17-010"]
    assert confirmed[0]["severity"] == "vulnerable"


def test_clean_run_says_how_many_checks_backed_that_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # "nothing found" must never be indistinguishable from "nothing ran"
    _box(tmp_path)
    clean = FIXTURE.read_text(encoding="utf-8").replace("  VULNERABLE:", "  NOT VULNERABLE:")
    clean = clean.replace("State: VULNERABLE", "State: NOT VULNERABLE")
    _stub_shell(monkeypatch, clean)
    result = runner.invoke(app, ["vuln", "smb", "-p", "box", "--workspace", str(tmp_path)])
    assert result.exit_code == 0
    assert "No script reported VULNERABLE" in result.output
    assert "check(s) came back clean" in result.output


def test_all_scans_every_family_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _box(tmp_path)
    commands = _stub_shell(monkeypatch, FIXTURE.read_text(encoding="utf-8"))
    result = runner.invoke(app, ["vuln", "-p", "box", "--all", "--workspace", str(tmp_path)])
    assert result.exit_code == 0
    assert len(commands) == 2  # smb (139+445) + rdp (3389)


def test_an_unknown_service_is_refused_with_the_choices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _box(tmp_path)
    result = runner.invoke(app, ["vuln", "gopher", "-p", "box", "--workspace", str(tmp_path)])
    assert result.exit_code == 2
    assert "not an open service" in result.output


def test_an_unknown_mode_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _box(tmp_path)
    result = runner.invoke(
        app, ["vuln", "smb", "-p", "box", "--mode", "bogus", "--workspace", str(tmp_path)]
    )
    assert result.exit_code == 2
    assert "--mode must be one of" in result.output


def test_safe_mode_drops_the_dos_checks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _box(tmp_path)
    commands = _stub_shell(monkeypatch, FIXTURE.read_text(encoding="utf-8"))
    runner.invoke(app, ["vuln", "smb", "-p", "box", "--mode", "safe", "--workspace", str(tmp_path)])
    assert "safe" in commands[0]


def test_a_box_with_no_services_says_to_scan_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    Profile.create(tmp_path, "empty", Target(ip="10.10.10.100")).save()
    result = runner.invoke(app, ["vuln", "-p", "empty", "--workspace", str(tmp_path)])
    assert result.exit_code == 0
    assert "run `nabu-cli scan` first" in result.output


def test_a_missing_tool_is_reported_not_swallowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _box(tmp_path)

    class Missing:
        missing_tool = "nmap"
        blocked = None
        exit_code = 127

    monkeypatch.setattr(cli_mod.shell, "run", lambda *a, **k: Missing())
    result = runner.invoke(app, ["vuln", "smb", "-p", "box", "--workspace", str(tmp_path)])
    assert result.exit_code == 0
    assert "nmap is not installed" in result.output
