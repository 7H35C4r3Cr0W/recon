from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from oscprecon import config
from oscprecon.gui.workspace.dashboard import WorkspaceDashboard
from oscprecon.models import Target
from oscprecon.profile import Profile


@pytest.fixture
def dashboard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, qtbot: QtBot) -> WorkspaceDashboard:
    monkeypatch.setattr(config, "workspace_root", lambda: tmp_path)
    widget = WorkspaceDashboard()
    qtbot.addWidget(widget)
    return widget


def _wait_rows(qtbot: QtBot, dash: WorkspaceDashboard, count: int) -> None:
    dash.refresh()
    qtbot.waitUntil(lambda: dash._table.rowCount() == count, timeout=4000)


def test_empty_workspace_shows_guidance(dashboard: WorkspaceDashboard, qtbot: QtBot) -> None:
    dashboard.refresh()
    qtbot.waitUntil(lambda: dashboard._stack.currentIndex() == 1, timeout=4000)  # empty page


def test_multiple_profiles_populate(
    tmp_path: Path, dashboard: WorkspaceDashboard, qtbot: QtBot
) -> None:
    Profile.create(tmp_path, "alpha", Target(ip="10.0.0.1"))
    Profile.create(tmp_path, "beta", Target(ip="10.0.0.2"))
    _wait_rows(qtbot, dashboard, 2)
    names = {dashboard._table.item(r, 0).text() for r in range(2)}
    assert any("alpha" in n for n in names) and any("beta" in n for n in names)


def test_refresh_does_not_duplicate(
    tmp_path: Path, dashboard: WorkspaceDashboard, qtbot: QtBot
) -> None:
    Profile.create(tmp_path, "a", Target(ip="10.0.0.1"))
    _wait_rows(qtbot, dashboard, 1)
    _wait_rows(qtbot, dashboard, 1)  # second refresh -> still 1 row, no duplicate


def test_open_signal_on_activate(
    tmp_path: Path, dashboard: WorkspaceDashboard, qtbot: QtBot
) -> None:
    prof = Profile.create(tmp_path, "a", Target(ip="10.0.0.1"))
    _wait_rows(qtbot, dashboard, 1)
    with qtbot.waitSignal(dashboard.open_requested) as blocker:
        dashboard._on_activated(dashboard._table.item(0, 0))
    assert Path(str(blocker.args[0])) == prof.directory


def test_filter_by_text(tmp_path: Path, dashboard: WorkspaceDashboard, qtbot: QtBot) -> None:
    Profile.create(tmp_path, "windows-box", Target(ip="10.0.0.1"))
    Profile.create(tmp_path, "linux-box", Target(ip="10.0.0.2"))
    _wait_rows(qtbot, dashboard, 2)
    dashboard._filter.setText("windows")
    assert dashboard._table.rowCount() == 1


def test_pin_and_status_and_archive_actions(
    tmp_path: Path, dashboard: WorkspaceDashboard, qtbot: QtBot
) -> None:
    prof = Profile.create(tmp_path, "a", Target(ip="10.0.0.1"))
    _wait_rows(qtbot, dashboard, 1)
    d = prof.directory
    dashboard._mutate([d], lambda p: p.set_pinned(True))
    qtbot.waitUntil(lambda: Profile.load(d).organization_meta().pinned, timeout=4000)
    dashboard._mutate([d], lambda p: p.set_status("completed"))
    qtbot.waitUntil(lambda: Profile.load(d).organization_meta().status == "completed", timeout=4000)
    dashboard._mutate([d], lambda p: p.add_tag("web"))
    qtbot.waitUntil(lambda: "web" in Profile.load(d).organization_meta().tags, timeout=4000)


def test_archive_hidden_until_toggled(
    tmp_path: Path, dashboard: WorkspaceDashboard, qtbot: QtBot
) -> None:
    prof = Profile.create(tmp_path, "a", Target(ip="10.0.0.1"))
    prof.set_archived(True)
    dashboard.refresh()
    qtbot.waitUntil(lambda: len(dashboard._summaries) == 1, timeout=4000)  # scan actually done
    assert dashboard._table.rowCount() == 0  # archived hidden by default
    dashboard._show_archived.setChecked(True)
    assert dashboard._table.rowCount() == 1


def test_corrupt_profile_shows_warning(
    tmp_path: Path, dashboard: WorkspaceDashboard, qtbot: QtBot
) -> None:
    prof = Profile.create(tmp_path, "broken", Target(ip="10.0.0.1"))
    prof.profile_json_path.write_text("{ corrupt")
    _wait_rows(qtbot, dashboard, 1)
    item = dashboard._table.item(0, 0)
    assert "⚠" in item.text()  # warning indicator


def test_credential_column_shows_count_not_secret(
    tmp_path: Path, dashboard: WorkspaceDashboard, qtbot: QtBot
) -> None:
    from oscprecon.models import Credential

    prof = Profile.create(tmp_path, "a", Target(ip="10.0.0.1"))
    prof.add_credential(Credential(username="svc", secret="TOPSECRET", source="smb"))
    _wait_rows(qtbot, dashboard, 1)
    all_text = " ".join(
        dashboard._table.item(0, c).text() for c in range(dashboard._table.columnCount())
    )
    assert "1" in all_text and "TOPSECRET" not in all_text  # count only, never the secret


def test_worker_cancellation_on_shutdown(tmp_path: Path, dashboard: WorkspaceDashboard) -> None:
    dashboard.refresh()
    dashboard.shutdown()  # must not hang / crash
    assert dashboard._index_worker is None or not dashboard._index_worker.isRunning()


def test_mutate_skips_profile_locked_by_another_instance(
    tmp_path: Path, dashboard: WorkspaceDashboard, qtbot: QtBot
) -> None:
    import json
    import os
    import socket

    from oscprecon.workspace import locks

    prof = Profile.create(tmp_path, "a", Target(ip="10.0.0.1"))
    foreign = locks.LockInfo(
        pid=os.getppid(), hostname=socket.gethostname(), app_version="1", started_at="t"
    )
    locks.lock_path(prof.directory).write_text(json.dumps(foreign.to_dict()))
    _wait_rows(qtbot, dashboard, 1)
    dashboard._mutate([prof.directory], lambda p: p.set_status("completed"))
    assert Profile.load(prof.directory).organization_meta().status == "active"  # untouched


def test_dashboard_edit_to_open_profile_is_not_clobbered(tmp_path: Path, qtbot: QtBot) -> None:
    # regression: a dashboard org edit on the currently-open profile must survive a later
    # self._profile.save() by the main window (which previously held a stale organization block).
    from oscprecon.gui.main_window import MainWindow

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(tmp_path, "a", Target(ip="10.0.0.1"))
    window._set_profile(prof)  # opens + locks + holds in memory
    window._dashboard._mutate([prof.directory], lambda p: p.set_status("completed"))
    window._profile.save()  # an ordinary later save must NOT revert the dashboard edit
    assert Profile.load(prof.directory).organization_meta().status == "completed"
    window._release_lock()
