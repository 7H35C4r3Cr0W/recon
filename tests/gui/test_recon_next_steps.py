from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon.gui import main_window as mw
from oscprecon.gui.main_window import MainWindow
from oscprecon.gui.widgets.tool_panel import ToolPanel
from oscprecon.models import Suggestion, Target
from oscprecon.profile import Profile


def test_tool_panel_set_suggestions_and_prefill(qtbot: QtBot) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_suggestions(
        [
            Suggestion(
                text="SMB signing disabled — relay candidate",
                command_template="netexec smb 10.0.0.1 --shares",
                source_pattern="smb: detail_contains=signing: disabled",
                source_box="fixture.md",
            ),
            Suggestion(text="advisory only", source_pattern="smb: x", source_box=None),
        ]
    )
    assert panel._next_steps.count() == 2
    # activating the row with a command pre-fills the builder + switches to the generic page
    panel._on_next_step_activated(panel._next_steps.item(0))
    assert "netexec smb 10.0.0.1" in panel._command.text()
    assert panel._stack.currentIndex() == 0
    # activating the advisory-only row does nothing (no command → no auto-run, no pre-fill)
    panel._command.clear()
    panel._on_next_step_activated(panel._next_steps.item(1))
    assert panel._command.text() == ""


def test_tool_panel_empty_suggestions_show_placeholder(qtbot: QtBot) -> None:
    panel = ToolPanel()
    qtbot.addWidget(panel)
    panel.set_suggestions([])
    assert panel._next_steps.count() == 1
    assert "No pattern suggestions" in panel._next_steps.item(0).text()


def test_main_window_refreshes_suggestions(
    qtbot: QtBot, tmp_path: Path, monkeypatch: object
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    monkeypatch.setattr(  # type: ignore[attr-defined]
        mw,
        "suggest_for",
        lambda findings, **kwargs: [Suggestion(text="do X", command_template="nmap 10.0.0.1")],
    )
    window._set_profile(Profile.create(tmp_path, "b", Target(ip="10.0.0.1")))
    assert window._tool_panel._next_steps.count() == 1
    assert "do X" in window._tool_panel._next_steps.item(0).text()
