import threading
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oscprecon import shell
from oscprecon.cli import app
from oscprecon.models import Target
from oscprecon.orchestrator import Orchestrator
from oscprecon.profile import Profile

_NMAP_OUT = "PORT   STATE SERVICE\n22/tcp open  ssh\n"


def _counting_run(calls: list[str]) -> Callable[..., object]:
    def run(
        shell_line: str,
        output_file: Path,
        *,
        cwd: Path | None = None,
        timeout: object | None = None,
        cancel: object | None = None,
        on_line: object | None = None,
    ) -> object:
        calls.append(shell_line)
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_NMAP_OUT, encoding="utf-8")
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    return run


def test_resume_skips_completed_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    first: list[str] = []
    monkeypatch.setattr(shell, "run", _counting_run(first))
    Orchestrator(prof).run_nmap()
    assert first  # the fresh scan actually executed commands

    second: list[str] = []
    monkeypatch.setattr(shell, "run", _counting_run(second))
    Orchestrator(Profile.load(prof.directory), resume=True).run_nmap()
    assert second == []  # every command reused its prior exit-0 output


def test_force_overrides_resume(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    monkeypatch.setattr(shell, "run", _counting_run([]))
    Orchestrator(prof).run_nmap()

    rerun: list[str] = []
    monkeypatch.setattr(shell, "run", _counting_run(rerun))
    Orchestrator(Profile.load(prof.directory), resume=True, force=True).run_nmap()
    assert rerun  # --force re-runs despite --resume


def test_resume_reruns_missing_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    monkeypatch.setattr(shell, "run", _counting_run([]))
    Orchestrator(prof).run_nmap()

    (prof.directory / "nmap" / "tcp-full.txt").unlink()  # simulate a lost/partial output
    rerun: list[str] = []
    monkeypatch.setattr(shell, "run", _counting_run(rerun))
    Orchestrator(Profile.load(prof.directory), resume=True).run_nmap()
    assert any("-p-" in line for line in rerun)  # the missing full sweep re-ran
    assert not any("--top-ports 1000" in line for line in rerun)  # the intact one was reused


def test_reusable_ignores_nonzero_exit(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    out_rel = "nmap/tcp-top1000.txt"
    (prof.directory / "nmap" / "tcp-top1000.txt").write_text(_NMAP_OUT, encoding="utf-8")
    prof.add_command(
        {"id": "cmd-001", "output_file": out_rel, "exit_code": 126, "shell_line": "nmap x"}
    )
    from oscprecon.models import Command

    cmd = Command("nmap", "nmap --top-ports 1000 x", "why", "< 1 min", out_rel)
    # a blocked/failed prior run (exit 126) must never be reused, even with a file present
    assert Orchestrator(prof, resume=True)._reusable(cmd) is False


def test_orchestrator_stops_when_precancelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    calls: list[str] = []
    monkeypatch.setattr(shell, "run", _counting_run(calls))
    cancel = threading.Event()
    cancel.set()  # cancelled before the first command -> the loop breaks immediately
    Orchestrator(prof, cancel=cancel).run_nmap()
    assert calls == []


def test_cli_resume_preserves_history(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(shell, "run", _counting_run(calls))
    runner = CliRunner()

    first = runner.invoke(app, ["scan", "10.10.10.5", "-p", "b", "--workspace", str(tmp_path)])
    assert first.exit_code == 0
    prior = len(Profile.load(tmp_path / "b").command_history)
    assert prior > 0

    calls.clear()
    resumed = runner.invoke(
        app, ["scan", "10.10.10.5", "-p", "b", "--workspace", str(tmp_path), "--resume"]
    )
    assert resumed.exit_code == 0
    assert calls == []  # nothing re-ran under --resume
    # history preserved (not wiped by a fresh Profile.create)
    assert len(Profile.load(tmp_path / "b").command_history) == prior
