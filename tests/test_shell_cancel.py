import threading
from pathlib import Path
from typing import Any

import pytest

from oscprecon import shell


class _FakeProc:
    # why: a stand-in for a long-running child — its stdout iterator blocks until kill() lands,
    # so shell.run's read loop only unblocks when the cancel monitor fires.
    def __init__(self) -> None:
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


def test_shell_run_cancel_kills_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shell.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    proc = _FakeProc()
    monkeypatch.setattr(shell.subprocess, "Popen", lambda *a, **k: proc, raising=True)

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

    cancel = threading.Event()
    # set the event shortly after run() starts, from another thread, to exercise the poll loop
    timer = threading.Timer(0.1, cancel.set)
    timer.start()
    try:
        result = shell.run("nmap -p- 10.0.0.1", tmp_path / "o.txt", cancel=cancel)
    finally:
        timer.cancel()

    assert result.cancelled is True
