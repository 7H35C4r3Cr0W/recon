from typing import Any

import pytest
from typer.testing import CliRunner

import oscprecon.cli as cli_mod
from oscprecon.cli import app

runner = CliRunner()


def test_scan_rejects_unknown_scan_profile() -> None:
    # the --scan-profile guard must reject an unknown value BEFORE creating a profile or running
    # nmap — a typo can't silently fall through to the default battery.
    result = runner.invoke(app, ["scan", "10.10.10.5", "--profile", "b", "--scan-profile", "bogus"])
    assert result.exit_code == 2
    assert "unknown --scan-profile" in result.output


def test_scan_threads_valid_profile_to_orchestrator(monkeypatch: pytest.MonkeyPatch) -> None:
    # a valid --scan-profile passes the guard and is threaded through to the Orchestrator (the real
    # nmap run is stubbed so the test stays fast and offline).
    captured: dict[str, Any] = {}

    class FakeOrch:
        def __init__(self, _profile: Any, **kwargs: Any) -> None:
            captured.update(kwargs)

        def run_nmap(self) -> None:
            captured["ran"] = True

    monkeypatch.setattr(cli_mod, "Orchestrator", FakeOrch)
    result = runner.invoke(app, ["scan", "10.10.10.5", "--profile", "b", "--scan-profile", "exam"])
    assert result.exit_code == 0
    assert captured["scan_profile"] == "exam" and captured["ran"]


def test_scan_resume_accepts_equivalent_host_bit_cidr(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    # regression: --resume compared the RAW ip arg vs the NORMALIZED stored target, so a host-bit
    # CIDR (10.10.5.5/24) was falsely rejected as a mismatch for a profile stored as 10.10.5.0/24.
    from oscprecon.models import Target
    from oscprecon.profile import Profile

    Profile.create(tmp_path, "net", Target(ip="10.10.5.0/24"))
    captured: dict[str, Any] = {}

    class FakeOrch:
        def __init__(self, _profile: Any, **kwargs: Any) -> None:
            pass

        def run_nmap(self) -> None:
            captured["ran"] = True

    monkeypatch.setattr(cli_mod, "Orchestrator", FakeOrch)
    result = runner.invoke(
        app,
        ["scan", "10.10.5.5/24", "--profile", "net", "--resume", "--workspace", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output  # the equivalent CIDR must not be a mismatch
    assert captured.get("ran")


def test_enum_lists_full_recon_modules() -> None:
    # regression: `enum` must expose the rich full modules (http/ssh/…), not just simple specs —
    # DarkCorp field-test found they were missing. No-arg lists the runnable services.
    result = runner.invoke(app, ["enum", "--profile", "x"])
    assert result.exit_code == 0
    for m in ("ssh", "http", "smb", "ldap", "dns", "ftp", "vhost"):
        assert m in result.stdout, m


def test_enum_full_module_resolver_maps_names() -> None:
    # the full-module names each resolve to a real recon Module class (no import/typo drift).
    import importlib
    import inspect

    from oscprecon.cli import _FULL_ENUM_MODULES
    from oscprecon.modules.base import Module

    for name in _FULL_ENUM_MODULES:
        mod = importlib.import_module(f"oscprecon.modules.{name}")
        cls = [
            o
            for _, o in inspect.getmembers(mod, inspect.isclass)
            if issubclass(o, Module) and o is not Module and o.__module__.startswith(mod.__name__)
        ]
        assert cls, f"no Module class for enum '{name}'"


def test_enum_http_auto_runs_wpscan_on_wordpress(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    # End-to-end: `enum http` fingerprints a web port, and when the output shows WordPress it must
    # AUTO-RUN wpscan enumeration and fold its findings (version/plugins/users) into findings.json —
    # not merely print a suggestion. shell.run is stubbed so no real tools/network are touched.
    from pathlib import Path

    from oscprecon import shell
    from oscprecon.models import Target
    from oscprecon.profile import Profile

    Profile.create(tmp_path, "wp", Target(ip="10.10.10.5"))
    wpscan_json = (Path(__file__).parent / "fixtures" / "http" / "wpscan.json").read_text()
    ran: list[str] = []

    def fake_run(shell_line: str, output_file: Path, **_: Any) -> Any:
        ran.append(shell_line)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        if shell_line.startswith("wpscan"):
            output_file.write_text(wpscan_json, encoding="utf-8")
        elif shell_line.startswith("whatweb"):
            output_file.write_text("http://10.10.10.5/ [200 OK] WordPress[5.8]", encoding="utf-8")
        else:
            output_file.write_text("", encoding="utf-8")
        return shell.ShellResult(
            shell_line=shell_line,
            exit_code=0,
            output_file=output_file,
            started_at="t",
            finished_at="t",
            duration_s=0.0,
        )

    monkeypatch.setattr("oscprecon.shell.run", fake_run)
    result = runner.invoke(app, ["enum", "http", "--profile", "wp", "--workspace", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "[wordpress] detected on port 80" in result.output
    # wpscan was actually invoked (enumeration flags, never brute)
    wp = next(c for c in ran if c.startswith("wpscan"))
    assert "--enumerate vp,vt,tt,cb,dbe,u,m" in wp and "--passwords" not in wp
    # and its results landed in findings.json
    findings_text = (tmp_path / "wp" / "findings.json").read_text(encoding="utf-8")
    assert "WordPress 5.8" in findings_text
    assert "akismet" in findings_text  # a plugin
    assert "admin" in findings_text  # an enumerated user
