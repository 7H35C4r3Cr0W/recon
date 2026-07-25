"""Regressions for the full-audit round: installer/doctor safety, CLI honesty, /etc/hosts input.

Each test names the behaviour that was wrong, so a future change that reintroduces it fails loudly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import oscprecon.cli as cli_mod
from oscprecon import doctor, hosts
from oscprecon.cli import app
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile
from oscprecon.workspace import activity as activity_mod

runner = CliRunner()


# --- doctor --install must not be able to break a rolling Kali ----------------------------------


def test_doctor_install_dry_runs_and_refuses_a_destructive_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # install.sh advertises "refuses to continue if apt would remove or downgrade anything".
    # `nabu-cli doctor --install` had none of that and ran a bare `apt-get install -y` per package.
    class Simulated:
        returncode = 0
        stdout = "Remv libssl3 [3.0.11]\nInst nmap (7.94 Kali:now)\n"
        stderr = ""

    monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: Simulated())
    ran: list[list[str]] = []
    plan = doctor.InstallPlan(("nmap",), ())
    lines: list[str] = []
    code = doctor.install(
        plan, assume_yes=True, runner=lambda argv: ran.append(argv) or 0, echo=lines.append
    )
    assert ran == [], "a plan that REMOVES a package must never reach a real apt-get install"
    assert code == 1
    assert any("SKIPPED" in line for line in lines)
    assert any("full-upgrade" in line for line in lines)


def test_doctor_install_proceeds_when_the_plan_is_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    class Simulated:
        returncode = 0
        stdout = "Inst nmap (7.94 Kali:now)\nConf nmap (7.94 Kali:now)\n"
        stderr = ""

    monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: Simulated())
    ran: list[list[str]] = []
    code = doctor.install(
        doctor.InstallPlan(("nmap",), ()),
        assume_yes=True,
        runner=lambda argv: ran.append(argv) or 0,
        echo=lambda _line: None,
    )
    assert code == 0
    assert ran and ran[0][-2:] == ["install", "nmap"] or "nmap" in ran[0]


# --- /etc/hosts is a system file: validate before writing ---------------------------------------


def test_hosts_refuses_a_non_ip_first_field(tmp_path: Path) -> None:
    path = tmp_path / "hosts"
    path.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not an IP address"):
        hosts.add_entry("notanip", ["box.htb"], path)
    assert path.read_text(encoding="utf-8") == "127.0.0.1 localhost\n"  # untouched


def test_hosts_refuses_a_malformed_hostname(tmp_path: Path) -> None:
    path = tmp_path / "hosts"
    path.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not a valid hostname"):
        hosts.add_entry("10.10.10.5", ["bad name"], path)


def test_hosts_still_accepts_a_real_mapping(tmp_path: Path) -> None:
    path = tmp_path / "hosts"
    path.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    hosts.add_entry("10.10.10.5", ["box.htb", "dc.box.htb"], path)
    assert "10.10.10.5" in path.read_text(encoding="utf-8")


# --- activity: the truncation notice must count EVENTS, not corrupt lines -----------------------


def test_activity_total_is_events_not_malformed_lines(tmp_path: Path) -> None:
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.100"))
    audit = profile.directory / "audit.jsonl"
    good = '{"ts": "2026-07-25T10:0%d:00Z", "actor": "user", "action": "run-command"}'
    audit.write_text("\n".join(good % i for i in range(5)) + "\nNOT JSON\n", encoding="utf-8")

    events, malformed = activity_mod.load_activity(profile.directory, limit=2)
    assert len(events) == 2
    assert malformed == 1  # the corrupt line, not a total
    assert activity_mod.count_activity(profile.directory) == 5

    result = runner.invoke(
        app, ["activity", "-p", "box", "--limit", "2", "--workspace", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert "3 older event(s) not shown" in result.output  # 5 total - 2 shown
    assert "1 unreadable audit line" in result.output


# --- CLI honesty: a flag must do what its help says, or say why not ------------------------------


def _box(tmp_path: Path) -> Profile:
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.100"))
    profile.set_services(
        [
            DiscoveredService(port=445, proto=Proto.TCP, service="microsoft-ds", discovered_at=""),
            DiscoveredService(port=139, proto=Proto.TCP, service="netbios-ssn", discovered_at=""),
        ]
    )
    profile.save()
    return profile


def test_vuln_port_and_all_are_mutually_exclusive(tmp_path: Path) -> None:
    _box(tmp_path)
    result = runner.invoke(
        app, ["vuln", "-p", "box", "--all", "--port", "445", "--workspace", str(tmp_path)]
    )
    assert result.exit_code == 2
    assert "one or the other" in result.output


def test_vuln_port_alone_scans_only_that_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _box(tmp_path)
    commands: list[str] = []

    class Result:
        missing_tool = None
        blocked = None
        exit_code = 0

    def fake_run(command: str, output_file: Path, **_kw: Any) -> Result:
        commands.append(command)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text("", encoding="utf-8")
        return Result()

    monkeypatch.setattr(cli_mod.shell, "run", fake_run)
    result = runner.invoke(
        app, ["vuln", "-p", "box", "--port", "445", "--workspace", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert commands and "-p 445 " in commands[0]  # not the whole 139,445 family


def test_enum_with_no_arguments_lists_services_without_a_profile() -> None:
    # its own first documented example — it used to die on the required --profile
    result = runner.invoke(app, ["enum"])
    assert result.exit_code == 0
    assert "smb" in result.output


def test_enum_with_a_service_still_demands_a_profile() -> None:
    result = runner.invoke(app, ["enum", "smb"])
    assert result.exit_code == 2
    assert "needs a project" in result.output


def test_exploit_suggested_without_a_profile_says_so(tmp_path: Path) -> None:
    result = runner.invoke(app, ["exploit", "smb", "--suggested", "--workspace", str(tmp_path)])
    assert result.exit_code == 2
    assert "--suggested ranks against a project" in result.output


def test_export_vault_help_does_not_promise_redaction() -> None:
    result = runner.invoke(app, ["export-vault", "--help"])
    assert result.exit_code == 0
    assert "redact" not in result.output.lower()  # §6: secrets are shown in full, and it says so


def test_delete_project_refuses_a_project_open_elsewhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from oscprecon.workspace import locks

    profile = _box(tmp_path)

    class Foreign:
        pid = 999999
        host = "other"

    monkeypatch.setattr(locks, "read_lock", lambda _d: (Foreign(), False))
    monkeypatch.setattr(locks, "is_stale", lambda _i: False)
    monkeypatch.setattr(locks, "is_ours", lambda _i: False)
    result = runner.invoke(
        app, ["delete-project", "-p", "box", "--yes", "--workspace", str(tmp_path)]
    )
    assert result.exit_code == 2
    assert "open in another Nabu window" in result.output
    assert profile.directory.exists()  # nothing was deleted


# --- `exploit` must build a command that could actually authenticate ------------------------------


def test_exploit_fills_one_credential_not_a_mix_of_two(tmp_path: Path) -> None:
    # taking the username from one entry and the hash from another produced a command that
    # authenticated as nobody: `-hashes <b's hash>` under `a`'s name.
    from oscprecon.models import Credential

    profile = _box(tmp_path)
    profile.add_credential(Credential(username="alice", secret="Summer2024!"))
    profile.add_credential(Credential(username="bob", secret="aad3b:31d6", secret_type="hash"))
    result = runner.invoke(app, ["exploit", "smb", "-p", "box", "--workspace", str(tmp_path)])
    assert result.exit_code == 0
    # alice is the primary (first password cred); bob's hash must not appear anywhere
    assert "aad3b:31d6" not in result.output


def test_exploit_does_not_append_a_port_to_a_non_web_url(tmp_path: Path) -> None:
    profile = _box(tmp_path)
    assert profile.directory.exists()
    result = runner.invoke(
        app, ["exploit", "smb", "-p", "box", "--port", "445", "--workspace", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert "://10.10.10.100:445" not in result.output  # http://host:445 is not a thing


def test_exploit_still_appends_the_port_for_a_web_service(tmp_path: Path) -> None:
    profile = Profile.create(tmp_path, "web", Target(ip="10.10.10.100"))
    profile.set_services(
        [DiscoveredService(port=8080, proto=Proto.TCP, service="http-proxy", discovered_at="")]
    )
    profile.save()
    result = runner.invoke(
        app, ["exploit", "web", "-p", "web", "--port", "8080", "--workspace", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert "://10.10.10.100:8080" in result.output
