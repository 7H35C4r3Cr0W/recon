from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from oscprecon import findings as findings_mod
from oscprecon.gui.main_window import MainWindow
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile


def _profile(tmp_path: Path) -> Profile:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    prof.set_services([DiscoveredService(445, Proto.TCP, "microsoft-ds")])
    findings_mod.add_findings(
        prof.directory,
        [{"module": "smb", "kind": "signing", "value": "disabled", "discovered_at": "t"}],
    )
    return prof


def test_key_controls_have_accessible_names(qtbot: QtBot) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    assert window._run_button.accessibleName() == "Run full recon"
    assert window._service_tree.accessibleName() == "Discovered services"
    assert window._tool_panel._output.accessibleName() == "Command output"
    assert window._tool_panel._command.accessibleName() == "Command to run"


def test_find_routes_to_active_view_search(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # offscreen focus is unreliable, so assert Ctrl+F ROUTES to the right view's search helper
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(_profile(tmp_path))
    calls: list[str] = []
    monkeypatch.setattr(window._findings_view, "focus_search", lambda: calls.append("findings"))
    monkeypatch.setattr(window._dashboard, "focus_filter", lambda: calls.append("workspace"))
    monkeypatch.setattr(window._reference_pane, "focus_find", lambda: calls.append("reference"))
    window._show_findings()
    window._on_find()
    window._show_recon()
    window._on_find()  # recon three-pane -> reference-pane find
    window._show_workspace()
    window._on_find()
    assert calls == ["findings", "reference", "workspace"]
    window._dashboard.shutdown()


def test_escape_dismisses_the_feedback_banner(qtbot: QtBot) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._tool_panel.append_output("[blocked] spray is gated")
    assert not window._tool_panel._banner.isHidden()
    window._on_escape()
    assert window._tool_panel._banner.isHidden()
