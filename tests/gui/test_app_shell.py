from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon import audit
from oscprecon import findings as findings_mod
from oscprecon.gui.main_window import MainWindow
from oscprecon.gui.widgets.activity_view import ActivityView
from oscprecon.gui.widgets.app_header import AppHeader
from oscprecon.gui.widgets.findings_view import FindingsView
from oscprecon.gui.widgets.nav_rail import ACTION_KEYS, PAGE_KEYS, NavRail
from oscprecon.models import DiscoveredService, Proto, Target
from oscprecon.profile import Profile


def _profile(tmp_path: Path) -> Profile:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5", hostname="box.htb"))
    prof.set_services([DiscoveredService(445, Proto.TCP, "microsoft-ds")])
    findings_mod.add_findings(
        prof.directory,
        [
            {"module": "smb", "kind": "signing", "value": "disabled", "discovered_at": "t"},
            {"module": "nmap", "kind": "product", "value": "OpenSSH 8.4", "discovered_at": "t"},
        ],
    )
    return prof


def test_nav_rail_emits_and_syncs(qtbot: QtBot) -> None:
    rail = NavRail()
    qtbot.addWidget(rail)
    seen: list[str] = []
    rail.navigate.connect(seen.append)
    rail._buttons["graph"].click()
    rail._buttons["credentials"].click()
    assert seen == ["graph", "credentials"]
    # page items hold state; action items never do
    rail.set_current("graph")
    assert rail._buttons["graph"].isChecked()
    assert not rail._buttons["credentials"].isCheckable()
    assert set(PAGE_KEYS).isdisjoint(ACTION_KEYS)


def test_nav_rail_gates_on_profile(qtbot: QtBot) -> None:
    rail = NavRail()
    qtbot.addWidget(rail)
    rail.set_enabled_keys(False)
    assert rail._buttons["workspace"].isEnabled()  # always reachable
    assert not rail._buttons["recon"].isEnabled()
    rail.set_enabled_keys(True)
    assert rail._buttons["recon"].isEnabled()


def test_app_header_reflects_state(qtbot: QtBot) -> None:
    header = AppHeader()
    qtbot.addWidget(header)
    header.set_profile("htb-active", "10.10.10.100", "active.htb", read_only=True)
    assert header._project.text() == "htb-active"
    assert "10.10.10.100" in header._target.text() and "active.htb" in header._target.text()
    assert (
        not header._read_only.isHidden()
    )  # offscreen: isHidden reflects setVisible, isVisible not
    header.set_task_count(3)
    assert "3" in header._tasks.text()
    header.set_task_count(0)
    assert header._tasks.text() == ""
    header.clear_profile()
    assert header._read_only.isHidden()


def test_findings_view_uses_conservative_categories(qtbot: QtBot, tmp_path: Path) -> None:
    view = FindingsView()
    qtbot.addWidget(view)
    view.set_profile(_profile(tmp_path))
    labels = {
        view._table.item(r, 2).text(): view._table.item(r, 0).text()
        for r in range(view._table.rowCount())
    }
    assert labels["signing"] == "relay-risk"  # weak posture
    assert labels["product"] == "info"  # a version banner is never a vuln
    assert "1 notable" in view._summary.text()


def test_findings_view_search_and_category_filter(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    findings_mod.add_findings(
        prof.directory,
        [
            {"module": "smb", "kind": "signing", "value": "disabled", "discovered_at": "t"},
            {"module": "ssh", "kind": "product", "value": "OpenSSH 8.4", "discovered_at": "t"},
            {"module": "ftp", "kind": "auth", "value": "anonymous", "discovered_at": "t"},
        ],
    )
    view = FindingsView()
    qtbot.addWidget(view)
    view.set_profile(prof)
    assert view._table.rowCount() == 3  # all shown by default

    view._filter.setText("ssh")  # text search narrows to the ssh finding
    assert view._table.rowCount() == 1
    assert "of 3" in view._summary.text()  # count reflects the filter

    view._filter.setText("")
    view._category.setCurrentText("Notable only")  # info (product) drops out
    kinds = {view._table.item(r, 2).text() for r in range(view._table.rowCount())}
    assert kinds == {"signing", "auth"}  # both notable; the version banner is filtered away

    # the "N notable" count reflects the SHOWN rows, not the whole set (regression: was over _all)
    view._category.setCurrentText("info")  # only the non-notable product row is shown
    assert view._table.rowCount() == 1
    assert "0 notable" in view._summary.text()  # nothing notable is on screen


def test_activity_view_lists_audit_events(qtbot: QtBot, tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    audit.record(prof.directory, prof.profile_name, "run-command", details={"module": "nmap"})
    view = ActivityView()
    qtbot.addWidget(view)
    view.set_profile(prof)
    assert view._table.rowCount() == 1
    assert view._table.item(0, 2).text() == "run-command"


def test_main_window_nav_switches_pages(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(_profile(tmp_path))
    # loading a profile lands on Recon and enables the rail
    assert window._central_stack.currentIndex() == 0
    assert window._nav._buttons["recon"].isChecked()
    assert window._nav._buttons["findings"].isEnabled()

    window._on_navigate("findings")
    assert window._central_stack.currentWidget() is window._findings_view
    assert window._nav._buttons["findings"].isChecked()

    window._on_navigate("activity")
    assert window._central_stack.currentWidget() is window._activity_view

    window._on_navigate("graph")
    assert window._central_stack.currentIndex() == 1
    assert window._graph_action.isChecked()

    window._on_navigate("recon")
    assert window._central_stack.currentIndex() == 0
    window._dashboard.shutdown()


def test_main_window_header_tracks_profile(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(_profile(tmp_path))
    assert window._header._project.text() == "b"
    assert "10.10.10.5" in window._header._target.text()
    window._dashboard.shutdown()
