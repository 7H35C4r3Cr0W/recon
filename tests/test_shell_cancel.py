import contextlib
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from oscprecon import shell


class _FakeProc:
    # why: a stand-in for a long-running child — its stdout iterator blocks until kill() lands,
    # so shell.run's read loop only unblocks when the cancel monitor fires.
    def __init__(self) -> None:
        self.pid = 4242
        self.returncode: int | None = None
        self._done = threading.Event()
        self.stdout = self

    def __iter__(self) -> "_FakeProc":
        return self

    def __next__(self) -> str:
        self._done.wait()
        raise StopIteration

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9
        self._done.set()

    def wait(self, timeout: float | None = None) -> int:
        self._done.wait(timeout)
        return self.returncode if self.returncode is not None else 0


def _route_group_kill(monkeypatch: pytest.MonkeyPatch, proc: _FakeProc) -> None:
    # shell._terminate kills the whole process group; route that onto the fake's kill().
    monkeypatch.setattr(shell.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(shell.os, "killpg", lambda pgid, sig: proc.kill())


def test_shell_run_cancel_kills_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shell.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    proc = _FakeProc()
    monkeypatch.setattr(shell.subprocess, "Popen", lambda *a, **k: proc, raising=True)
    _route_group_kill(monkeypatch, proc)

    cancel = threading.Event()
    cancel.set()  # pre-cancelled -> the monitor kills on its first poll
    result = shell.run("nmap -p- 10.0.0.1", tmp_path / "o.txt", cancel=cancel)

    assert result.cancelled is True
    assert proc.returncode == -9


def _popen_factory(proc: _FakeProc) -> Any:
    return lambda *a, **k: proc


def test_shell_run_cancel_midflight(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shell.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    proc = _FakeProc()
    monkeypatch.setattr(shell.subprocess, "Popen", _popen_factory(proc))
    _route_group_kill(monkeypatch, proc)

    cancel = threading.Event()
    # set the event shortly after run() starts, from another thread, to exercise the poll loop
    timer = threading.Timer(0.1, cancel.set)
    timer.start()
    try:
        result = shell.run("nmap -p- 10.0.0.1", tmp_path / "o.txt", cancel=cancel)
    finally:
        timer.cancel()

    assert result.cancelled is True


@pytest.mark.skipif(not hasattr(os, "killpg"), reason="POSIX process groups only")
def test_terminate_kills_whole_process_group() -> None:
    # the direct child forks a grandchild (sleep) and prints its PID, then blocks. _terminate must
    # SIGKILL the whole group so the grandchild dies too — proc.kill() alone would orphan it.
    proc = subprocess.Popen(
        ["sh", "-c", "sleep 30 & echo $!; sleep 30"],
        stdout=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    assert proc.stdout is not None
    grandchild = int(proc.stdout.readline().strip())
    try:
        shell._terminate(proc)
        proc.wait(timeout=5)
        # poll until the grandchild is reaped (SIGKILL delivery is async)
        deadline = time.monotonic() + 5
        alive = True
        while time.monotonic() < deadline:
            try:
                os.kill(grandchild, 0)
                time.sleep(0.02)
            except ProcessLookupError:
                alive = False
                break
        assert alive is False  # killed via the process group, not left orphaned
    finally:
        for pid in (grandchild, proc.pid):
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, 9)
