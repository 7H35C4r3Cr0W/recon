from pathlib import Path

import pytest
from PySide6.QtGui import QDesktopServices
from pytestqt.qtbot import QtBot

from oscprecon.gui.main_window import MainWindow
from oscprecon.gui.widgets.report_view import ReportView
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile


def test_report_view_renders_markdown(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "htb-active", Target(ip="10.10.10.100"))
    prof.set_services(
        [DiscoveredService(port=445, proto=Proto.TCP, service="microsoft-ds", discovered_at="")]
    )
    view = ReportView()
    qtbot.addWidget(view)
    view.set_profile(prof)
    rendered = view._browser.toPlainText()
    assert "htb-active" in rendered
    assert "Discovered services" in rendered  # section heading rendered from the markdown


def test_report_view_empty_without_profile(qtbot: QtBot) -> None:
    view = ReportView()
    qtbot.addWidget(view)
    assert "No profile loaded" in view._browser.toPlainText()


def test_open_in_editor_writes_report_and_opens(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    view = ReportView()
    qtbot.addWidget(view)
    view.set_profile(prof)
    opened: list[str] = []
    monkeypatch.setattr(
        QDesktopServices, "openUrl", staticmethod(lambda url: opened.append(url.toLocalFile()))
    )
    view._on_open_in_editor()
    assert (prof.directory / "report.md").exists()  # persisted to disk
    assert opened and opened[0].endswith("report.md")  # handed to the OS


def test_report_toggle_switches_stack_and_is_exclusive_with_graph(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(tmp_path, "b", Target(ip="10.10.10.5")))

    window._graph_action.setChecked(True)
    assert window._central_stack.currentIndex() == 1

    window._report_action.setChecked(True)  # switching to report must uncheck graph
    assert window._central_stack.currentIndex() == 2
    assert window._graph_action.isChecked() is False

    window._report_action.setChecked(False)  # back to the three-pane view
    assert window._central_stack.currentIndex() == 0
