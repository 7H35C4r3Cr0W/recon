"""A scan must never be a black box: print the whole nmap plan BEFORE running it.

The operator's complaint was exact: "I don't even know what nmap syntax it's using other than 'run
full recon'". You learned each command only as it started, minutes apart, and the pre-flight ping
streamed its output with nothing saying what had been run.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from oscprecon import shell
from oscprecon.models import Target
from oscprecon.modules.nmap import NmapModule
from oscprecon.orchestrator import Orchestrator
from oscprecon.profile import Profile

_NMAP_OUT = "PORT   STATE SERVICE\n22/tcp open  ssh\n"


def _fake_run() -> Callable[..., object]:
    def run(shell_line: str, output_file: Path, **_kw: object) -> object:
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_NMAP_OUT, encoding="utf-8")
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    return run


# --- the plan itself ------------------------------------------------------------------------------


@pytest.mark.parametrize("profile", ["quick", "default", "full", "exam"])
def test_every_profile_publishes_a_plan(profile: str) -> None:
    planned = NmapModule(scan_profile=profile).plan(Target(ip="10.10.10.5"))
    assert planned
    for cmd in planned:
        assert cmd.shell_line.startswith("nmap ")
        assert cmd.why and cmd.expected_runtime_hint  # §7: both exist FOR the UI — so show them


def test_the_plan_includes_the_versioned_scan_it_cannot_spell_yet() -> None:
    # the -p list is only known after discovery; omitting the step entirely would understate the
    # scan, so it is shown with a placeholder
    lines = [c.shell_line for c in NmapModule(scan_profile="quick").plan(Target(ip="10.10.10.5"))]
    assert "nmap -sV -sC -p <discovered ports> 10.10.10.5" in lines


def test_the_plan_matches_what_the_battery_actually_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # a plan that drifts from the run is worse than no plan
    target = Target(ip="10.10.10.5")
    profile = Profile.create(tmp_path, "box", target)
    lines: list[str] = []
    monkeypatch.setattr(shell, "run", _fake_run())
    orch = Orchestrator(profile, scan_profile="full", on_line=lines.append)
    orch.run_nmap()

    ran = [line[2:] for line in lines if line.startswith("$ ")]
    planned = [c.shell_line for c in NmapModule(scan_profile="full").plan(target)]
    # same commands in the same order, with the placeholder resolved to the discovered port
    assert [p.replace("<discovered ports>", "22") for p in planned] == ran


@pytest.mark.parametrize("profile", ["quick", "default", "full", "exam"])
def test_the_plan_is_printed_before_anything_runs(
    profile: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = Profile.create(tmp_path, f"box-{profile}", Target(ip="10.10.10.5"))
    lines: list[str] = []
    monkeypatch.setattr(shell, "run", _fake_run())
    Orchestrator(prof, scan_profile=profile, on_line=lines.append).run_nmap()

    header = next(i for i, line in enumerate(lines) if line.startswith("[plan]"))
    first_run = next(i for i, line in enumerate(lines) if line.startswith("$ "))
    assert header < first_run
    assert f"scan profile '{profile}'" in lines[header]
    # every planned command's syntax is on screen before the first one starts
    plan_block = "\n".join(lines[header:first_run])
    for cmd in NmapModule(scan_profile=profile).plan(prof.target):
        assert cmd.shell_line in plan_block
        assert cmd.why in plan_block


# --- the pre-flight ping --------------------------------------------------------------------------


def test_the_preflight_ping_echoes_its_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("PySide6")
    from oscprecon.gui.workers.scans import PingWorker

    seen: list[str] = []

    def run(shell_line: str, output_file: Path, **kw: object) -> object:
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("Nmap scan report for 10.10.10.5\nHost is up (0.05s latency).\n", "utf-8")
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    monkeypatch.setattr(shell, "run", run)
    worker = PingWorker("10.10.10.5", tmp_path / "ping.txt")
    worker.line.connect(seen.append)
    worker.run()

    assert any(line.startswith("$ nmap -sn ") for line in seen), seen


# --- both front-ends can show the plan without scanning -------------------------------------------


def test_cli_dry_run_prints_the_syntax_and_creates_nothing(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from oscprecon.cli import app

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "10.10.10.5",
            "-p",
            "box",
            "--scan-profile",
            "full",
            "--dry-run",
            "--workspace",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "nmap --top-ports 1000 10.10.10.5" in result.output
    assert "nmap -sU -p- 10.10.10.5" in result.output  # the deferred sweep is disclosed too
    assert "nothing ran" in result.output
    assert not (tmp_path / "box").exists()  # a preview must not create a project


def test_gui_show_scan_plan_streams_the_same_commands(qtbot: object, tmp_path: Path) -> None:
    pytest.importorskip("PySide6")
    from oscprecon import config
    from oscprecon.gui.main_window import MainWindow

    window = MainWindow()
    try:
        window._set_profile(Profile.create(tmp_path, "box", Target(ip="10.10.10.5")))
        window._on_show_scan_plan()
        shown = window._tool_panel._output.toPlainText()
    finally:
        window.close()

    assert "[dry-run]" in shown and "nothing ran" in shown
    # the plan shown is the one the CONFIGURED profile would run — same source as the real battery
    configured = config.load_settings().scan_profile
    for cmd in NmapModule(scan_profile=configured).plan(Target(ip="10.10.10.5")):
        assert cmd.shell_line in shown
