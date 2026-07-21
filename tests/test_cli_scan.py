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
