from __future__ import annotations

import logging
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from oscprecon import config, diagnostics


@pytest.fixture
def diag() -> Iterator[None]:
    # why: install() mutates process globals (root log handler + sys.excepthook + a flag); snapshot
    # and restore all of it so these tests never leak into each other or the suite.
    # XDG_STATE_HOME is already redirected to a tmp dir by the autouse conftest fixture.
    diagnostics._installed = False
    orig_hook = sys.excepthook
    root = logging.getLogger()
    orig_handlers = list(root.handlers)
    orig_level = root.level
    try:
        yield
    finally:
        sys.excepthook = orig_hook
        for handler in list(root.handlers):
            if handler not in orig_handlers:
                root.removeHandler(handler)
                handler.close()
        root.setLevel(orig_level)
        diagnostics._installed = False


def test_state_dir_honours_xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    assert config.state_dir() == tmp_path / "xdg" / config.APP_NAME
    assert config.state_dir().is_dir()


def test_install_creates_log_and_is_idempotent(diag: None) -> None:
    path = diagnostics.install("cli")
    assert path is not None
    assert path == diagnostics.log_path()
    assert path.exists()
    assert path.parent.name == "logs"
    assert "session start" in path.read_text(encoding="utf-8")

    root = logging.getLogger()
    handlers_after_first = len(root.handlers)
    # a second install must not stack a duplicate file handler
    assert diagnostics.install("cli") == path
    assert len(root.handlers) == handlers_after_first


def test_logging_appends_to_file(diag: None) -> None:
    diagnostics.install("cli")
    diagnostics.get_logger().info("hello-marker-info")
    diagnostics.get_logger().error("boom-marker-error")
    text = diagnostics.log_path().read_text(encoding="utf-8")
    assert "hello-marker-info" in text
    assert "boom-marker-error" in text
    assert "ERROR" in text


def test_read_tail_empty_when_no_log(diag: None) -> None:
    # not installed → no file yet
    assert diagnostics.read_tail() == ""


def test_read_tail_returns_recent_and_bounds_size(diag: None) -> None:
    diagnostics.install("cli")
    log = diagnostics.get_logger()
    for i in range(5000):
        log.info("line-%05d-filler-content-to-grow-the-log", i)
    tail = diagnostics.read_tail(max_bytes=4000)
    assert tail  # non-empty
    assert len(tail.encode("utf-8")) <= 4000
    assert "line-04999" in tail  # the newest line survives
    assert "line-00000" not in tail  # the oldest is trimmed off the front


def test_clear_truncates(diag: None) -> None:
    diagnostics.install("cli")
    diagnostics.get_logger().error("to-be-cleared-marker")
    assert "to-be-cleared-marker" in diagnostics.log_path().read_text(encoding="utf-8")
    assert diagnostics.clear() is True
    assert "to-be-cleared-marker" not in diagnostics.log_path().read_text(encoding="utf-8")


def test_excepthook_logs_and_chains(diag: None) -> None:
    seen: list[BaseException] = []

    def previous(_t: object, exc: BaseException, _tb: object) -> None:
        seen.append(exc)

    sys.excepthook = previous  # type: ignore[assignment]  # install() will chain to this
    diagnostics.install("cli")
    assert sys.excepthook is not previous  # our hook is now in front

    err = ValueError("uncaught-boom-marker")
    sys.excepthook(type(err), err, None)

    assert seen == [err]  # the previous hook still ran (chained)
    text = diagnostics.log_path().read_text(encoding="utf-8")
    assert "uncaught exception" in text
    assert "uncaught-boom-marker" in text  # traceback body is logged


def test_install_qt_message_handler_is_best_effort(diag: None) -> None:
    # must not raise even without a QApplication; restore Qt's default handler afterwards.
    from PySide6.QtCore import qInstallMessageHandler

    try:
        diagnostics.install_qt_message_handler()
    finally:
        qInstallMessageHandler(None)  # don't leak the handler into other tests
