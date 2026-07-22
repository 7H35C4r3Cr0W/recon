from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon import config, edb
from oscprecon.gui.main_window import MainWindow
from oscprecon.models import Target
from oscprecon.profile import Profile
from oscprecon.references import ExploitHit


def _hit() -> ExploitHit:
    return ExploitHit(
        edb_id="12345",
        title="nginx example",
        url="https://www.exploit-db.com/exploits/12345",
        path="linux/remote/12345.py",
    )


def test_persist_edb_writes_store(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "b", Target(ip="10.0.0.1"))
    window._set_profile(prof)
    # profile + context are captured at lookup launch and passed through (bug #3 fix)
    window._persist_edb([_hit()], prof, ("80/tcp http", "nginx", "1.18"))
    rows = edb.load_edb(prof.directory)
    assert rows and rows[0]["edb_id"] == "12345" and rows[0]["service"] == "80/tcp http"


def test_persist_edb_skips_read_only(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "b", Target(ip="10.0.0.1"))
    window._set_profile(prof)
    prof.read_only = True
    window._persist_edb([_hit()], prof, ("80/tcp http", "nginx", "1.18"))
    assert not edb.edb_path(prof.directory).exists()  # no writes in read-only mode


def test_edb_persists_to_originating_profile_after_switch(qtbot: QtBot, tmp_path: Path) -> None:
    # bug #3: a lookup launched under project A that completes after the user switches to project B
    # must write into A (captured at launch), never B (the now-active profile).
    from oscprecon.references import EdbSearch

    window = MainWindow()
    qtbot.addWidget(window)
    a = Profile.create(config.workspace_root(), "proj-a", Target(ip="10.0.0.1"))
    b = Profile.create(config.workspace_root(), "proj-b", Target(ip="10.0.0.2"))
    window._set_profile(a)
    window._set_profile(b)  # user switched to B while A's lookup was in flight
    search = EdbSearch([_hit()], "nginx 1.18", "version")
    window._on_edb_done(search, window._edb_request_id, a, ("80/tcp http", "nginx", "1.18"))
    assert edb.load_edb(a.directory)  # A got the hits
    assert not edb.edb_path(b.directory).exists()  # B was never contaminated


def test_edb_persist_does_not_resurrect_a_deleted_project(qtbot: QtBot, tmp_path: Path) -> None:
    # bug: deleting the active project while a searchsploit lookup was in flight let add_edb mkdir
    # the folder back and write edb.json (a zombie stub). _persist_edb must skip a gone directory.
    import shutil

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "gone", Target(ip="10.0.0.1"))
    d = prof.directory
    shutil.rmtree(d)  # simulate the project being deleted mid-lookup
    window._persist_edb([_hit()], prof, ("80/tcp http", "nginx", "1.18"))
    assert not d.exists()  # not resurrected


def test_certsrv_enroll_template_uses_a_single_backslash() -> None:
    from oscprecon.exploit import ad

    tpl = next(a for a in ad._ACTIONS if a.id == "certsrv-web-enroll-cert").template
    assert "{domain}\\{user}" in tpl and "\\\\" not in tpl  # one literal backslash, not two
