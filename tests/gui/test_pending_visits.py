"""Finding #7: buffered reference-page visits must flush to the profile they were recorded under,
never the profile that happens to be active when a background worker completes."""

from __future__ import annotations

from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon import config
from oscprecon.gui.main_window import MainWindow
from oscprecon.models import Target
from oscprecon.profile import Profile


def test_pending_visits_flush_to_originating_profile(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    a = Profile.create(config.workspace_root(), "visits-a", Target(ip="10.0.0.1"))
    b = Profile.create(config.workspace_root(), "visits-b", Target(ip="10.0.0.2"))

    window._set_profile(a)
    # a visit buffered while a scan is active under project A
    window._pending_visits.append(("SMB", "https://ht/smb", str(a.directory)))

    window._set_profile(b)  # user switches to B while A's worker is still running
    window._post_run_refresh()  # A's worker completes and fires the flush

    # B must never be contaminated with A's visit; it stays buffered for A
    assert not any(v.get("url") == "https://ht/smb" for v in window._profile.references_visited)
    assert window._pending_visits  # retained, not dropped

    window._set_profile(a)  # switch back to A
    window._post_run_refresh()
    assert any(v.get("url") == "https://ht/smb" for v in window._profile.references_visited)
    assert not window._pending_visits  # now flushed to the correct project
