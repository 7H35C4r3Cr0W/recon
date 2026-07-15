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


def _down_run(
    shell_line: str,
    output_file: Path,
    *,
    cwd: Path | None = None,
    timeout: object | None = None,
    cancel: object | None = None,
    on_line: object | None = None,
) -> object:
    out = Path(output_file)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("Note: Host seems down. No response.\n", encoding="utf-8")
    return shell.ShellResult(shell_line, 0, out, "", "", 0.0)


def test_zero_open_ports_emits_hint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prof = Profile.create(tmp_path, "down", Target(ip="192.0.2.1"))
    monkeypatch.setattr(shell, "run", _down_run)
    lines: list[str] = []
    Orchestrator(prof, on_line=lines.append).run_nmap()
    assert prof.discovered_services == []
    assert any("[done] 0 services" in ln for ln in lines)
    assert any(ln.startswith("[hint] no open ports") for ln in lines)


def _redirect_run(host_line: str) -> Callable[..., object]:
    def run(shell_line: str, output_file: Path, **_: object) -> object:
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(f"80/tcp open  http nginx 1.14.2\n{host_line}\n", encoding="utf-8")
        return shell.ShellResult(shell_line, 0, out, "", "", 0.0)

    return run


def test_nmap_redirect_autoset_hostname(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Ignition: nmap's http-title redirect auto-wires the vhost when none is set (announced).
    prof = Profile.create(tmp_path, "ign", Target(ip="10.10.10.5"))
    monkeypatch.setattr(
        shell, "run", _redirect_run("|_http-title: Did not follow redirect to http://ignition.htb/")
    )
    lines: list[str] = []
    Orchestrator(prof, on_line=lines.append).run_nmap()
    assert prof.target.hostname == "ignition.htb"  # auto-set from the redirect
    assert any("set target hostname = ignition.htb" in ln for ln in lines)  # announced, not silent


def test_nmap_redirect_does_not_override_existing_hostname(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = Profile.create(tmp_path, "ign", Target(ip="10.10.10.5", hostname="chosen.htb"))
    monkeypatch.setattr(
        shell, "run", _redirect_run("|_http-title: Did not follow redirect to http://ignition.htb/")
    )
    lines: list[str] = []
    Orchestrator(prof, on_line=lines.append).run_nmap()
    assert prof.target.hostname == "chosen.htb"  # a user-set hostname is never overridden
    assert any(
        "nmap redirects to 'ignition.htb'" in ln for ln in lines
    )  # surfaced as a hint instead


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
    from oscprecon.models import Command

    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    out_rel = "nmap/tcp-top1000.txt"
    (prof.directory / "nmap" / "tcp-top1000.txt").write_text(_NMAP_OUT, encoding="utf-8")
    shell_line = "nmap --top-ports 1000 x"
    prof.add_command(
        {"id": "cmd-001", "output_file": out_rel, "exit_code": 126, "shell_line": shell_line}
    )
    cmd = Command("nmap", shell_line, "why", "< 1 min", out_rel)
    # a blocked/failed prior run (exit 126) must never be reused, even with a file present
    assert Orchestrator(prof, resume=True)._reusable(cmd) is False


def test_reusable_honours_latest_entry_not_any_exit0(tmp_path: Path) -> None:
    from oscprecon.models import Command

    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    out_rel = "nmap/tcp-full.txt"
    (prof.directory / "nmap" / "tcp-full.txt").write_text(_NMAP_OUT, encoding="utf-8")
    shell_line = "nmap -p- x"
    # an earlier clean run, then a later force-run that truncated + was cancelled (exit -9)
    prof.add_command(
        {"id": "cmd-001", "output_file": out_rel, "exit_code": 0, "shell_line": shell_line}
    )
    prof.add_command(
        {"id": "cmd-002", "output_file": out_rel, "exit_code": -9, "shell_line": shell_line}
    )
    cmd = Command("nmap", shell_line, "why", "5-15 min", out_rel)
    # the LATEST entry (-9) wins — the stale exit-0 must not resurrect the truncated file
    assert Orchestrator(prof, resume=True)._reusable(cmd) is False


def test_reusable_reruns_when_command_args_changed(tmp_path: Path) -> None:
    from oscprecon.models import Command

    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    out_rel = "nmap/tcp-versioned.txt"
    (prof.directory / "nmap" / "tcp-versioned.txt").write_text(_NMAP_OUT, encoding="utf-8")
    prof.add_command(
        {
            "id": "cmd-001",
            "output_file": out_rel,
            "exit_code": 0,
            "shell_line": "nmap -sV -sC -p 80,443 x",
        }
    )
    # a later resume discovered 8080 -> the versioned command's -p set changed but the output_file
    # is the same; the file must NOT be reused (8080 would never get versioned)
    cmd = Command("nmap", "nmap -sV -sC -p 80,443,8080 x", "why", "1-5 min", out_rel)
    assert Orchestrator(prof, resume=True)._reusable(cmd) is False


def test_full_profile_runs_udp_full_after_versioned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the `full` profile's slow UDP -p- sweep must run LAST — after the versioned -sV -sC scan — so
    # the high-value TCP service versions land before the hours-slow UDP sweep starts.
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    calls: list[str] = []
    monkeypatch.setattr(shell, "run", _counting_run(calls))
    Orchestrator(prof, scan_profile="full").run_nmap()
    versioned = next(i for i, c in enumerate(calls) if "-sV -sC" in c)
    udp_full = next(i for i, c in enumerate(calls) if "-sU -p-" in c)
    assert udp_full > versioned  # UDP -p- is deferred to run after the versioned scan


def test_default_profile_never_runs_udp_full(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    calls: list[str] = []
    monkeypatch.setattr(shell, "run", _counting_run(calls))
    Orchestrator(prof, scan_profile="default").run_nmap()
    assert not any("-sU -p-" in c for c in calls)  # default never runs the full UDP sweep


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


def test_cli_resume_rejects_target_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shell, "run", _counting_run([]))
    runner = CliRunner()
    first = runner.invoke(app, ["scan", "10.10.10.5", "-p", "b", "--workspace", str(tmp_path)])
    assert first.exit_code == 0
    # resuming with a DIFFERENT ip must error, not silently scan the stored target
    mismatch = runner.invoke(
        app, ["scan", "10.10.10.99", "-p", "b", "--workspace", str(tmp_path), "--resume"]
    )
    assert mismatch.exit_code == 2
    assert "target mismatch" in mismatch.output
