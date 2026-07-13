import io
import tarfile
from pathlib import Path

import pytest
from PySide6.QtWidgets import QFileDialog, QInputDialog, QMessageBox
from pytestqt.qtbot import QtBot

from oscprecon import config
from oscprecon.gui.main_window import MainWindow
from oscprecon.models import Target
from oscprecon.profile import Profile
from oscprecon.workspace import portability


def test_open_by_ip_opens_matching_profile(qtbot: QtBot, monkeypatch: pytest.MonkeyPatch) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    Profile.create(config.workspace_root(), "target-a", Target(ip="10.10.10.55"))
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("10.10.10.55", True))
    window._on_open_by_ip()
    assert window._profile is not None and window._profile.target.ip == "10.10.10.55"


def test_open_by_ip_no_match_leaves_profile(qtbot: QtBot, monkeypatch: pytest.MonkeyPatch) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("172.16.0.9", True))
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: QMessageBox.StandardButton.Ok)
    window._on_open_by_ip()
    assert window._profile is None  # nothing matched, nothing opened


def test_import_project_opens_imported(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    src = Profile.create(tmp_path / "src", "imported-box", Target(ip="10.9.9.9"))
    archive = portability.export_project_archive(src.directory, tmp_path)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(archive), ""))
    window._on_import_project()
    assert window._profile is not None and window._profile.profile_name == "imported-box"
    assert (config.workspace_root() / "imported-box" / "profile.json").is_file()


def test_import_collision_prompts_and_overwrites(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    dup = Profile.create(config.workspace_root(), "dup", Target(ip="10.2.2.2"))
    archive = portability.export_project_archive(dup.directory, tmp_path)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(archive), ""))
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    window._on_import_project()  # dup exists → prompt → overwrite
    assert window._profile is not None and window._profile.profile_name == "dup"


def test_import_malicious_archive_warns_and_opens_nothing(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(bad, "w:gz") as tar:
        info = tarfile.TarInfo("proj/../../pwned")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    window = MainWindow()
    qtbot.addWidget(window)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(bad), ""))
    warned: list[str] = []
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda *a, **k: warned.append(a[-1]) or QMessageBox.StandardButton.Ok,
    )
    window._on_import_project()
    assert window._profile is None  # nothing opened
    assert warned and "traversal" in warned[0]
    assert not (tmp_path / "pwned").exists()


def test_export_project_writes_archive(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "exportme", Target(ip="10.1.1.1"))
    window._set_profile(prof)
    out = tmp_path / "exportme.tar.gz"
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: QMessageBox.StandardButton.Ok)
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(out), ""))
    window._on_export_project()
    assert out.is_file()
    with tarfile.open(out) as tar:
        assert any(name.endswith("profile.json") for name in tar.getnames())


def test_export_project_cancelled_confirm_writes_nothing(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(config.workspace_root(), "x", Target(ip="10.1.1.2")))
    out = tmp_path / "x.tar.gz"
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: QMessageBox.StandardButton.Cancel)
    saved: list[str] = []
    monkeypatch.setattr(
        QFileDialog, "getSaveFileName", lambda *a, **k: saved.append("x") or ("", "")
    )
    window._on_export_project()
    assert (
        not out.exists() and not saved
    )  # declining the creds warning aborts before the file picker
