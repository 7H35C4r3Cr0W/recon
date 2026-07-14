from __future__ import annotations

import logging
import sys
from collections.abc import Iterator

import pytest
from pytestqt.qtbot import QtBot

from oscprecon import diagnostics
from oscprecon.gui.dialogs.log_viewer import LogViewerDialog
from oscprecon.gui.widgets.app_header import AppHeader


@pytest.fixture
def diag() -> Iterator[None]:
    # restore the global logging/excepthook state install() mutates (cf. test_diagnostics.py)
    diagnostics._installed = False
    orig_hook = sys.excepthook
    root = logging.getLogger()
    orig_handlers = list(root.handlers)
    try:
        yield
    finally:
        sys.excepthook = orig_hook
        for handler in list(root.handlers):
            if handler not in orig_handlers:
                root.removeHandler(handler)
                handler.close()
        diagnostics._installed = False


def test_log_viewer_shows_recent_entries(qtbot: QtBot, diag: None) -> None:
    diagnostics.install("gui")
    diagnostics.get_logger().error("gui-smoke-marker-42")
    dialog = LogViewerDialog()
    qtbot.addWidget(dialog)
    assert "gui-smoke-marker-42" in dialog._view.toPlainText()
    assert str(diagnostics.log_path()) in dialog._path_label.text()


def test_log_viewer_empty_state(qtbot: QtBot, diag: None) -> None:
    # no install() → no log file yet; the viewer shows a friendly placeholder, not a crash
    dialog = LogViewerDialog()
    qtbot.addWidget(dialog)
    assert "no log entries yet" in dialog._view.toPlainText()


def test_log_viewer_clear_empties_the_view(qtbot: QtBot, diag: None) -> None:
    diagnostics.install("gui")
    diagnostics.get_logger().error("clear-me-marker")
    dialog = LogViewerDialog()
    qtbot.addWidget(dialog)
    assert "clear-me-marker" in dialog._view.toPlainText()
    diagnostics.clear()
    dialog._reload()
    assert "clear-me-marker" not in dialog._view.toPlainText()


def test_header_carries_the_nabu_furby_brand(qtbot: QtBot) -> None:
    header = AppHeader()
    qtbot.addWidget(header)
    assert header._brand_name.text() == "Nabu"
    assert header._furby is not None
    assert header._brand.toolTip() == "Nabu — Local Recon Workspace"
    # restyling both themes must not raise (the brand name recolours to the accent)
    header.restyle("light")
    header.restyle("dark")
