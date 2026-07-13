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
    window._edb_context = ("80/tcp http", "nginx", "1.18")
    window._persist_edb([_hit()])
    rows = edb.load_edb(prof.directory)
    assert rows and rows[0]["edb_id"] == "12345" and rows[0]["service"] == "80/tcp http"


def test_persist_edb_skips_read_only(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "b", Target(ip="10.0.0.1"))
    window._set_profile(prof)
    window._profile.read_only = True  # type: ignore[union-attr]
    window._edb_context = ("80/tcp http", "nginx", "1.18")
    window._persist_edb([_hit()])
    assert not edb.edb_path(prof.directory).exists()  # no writes in read-only mode
