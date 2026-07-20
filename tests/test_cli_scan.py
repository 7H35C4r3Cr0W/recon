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
