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


# ---- project delete (dashboard right-click → confirm → host window removes the folder) --------


def test_delete_non_active_project_removes_folder(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "gone", Target(ip="10.3.3.3"))
    assert prof.directory.is_dir()
    window._on_delete_requested([str(prof.directory)])
    assert not prof.directory.exists()
    window.close()  # closeEvent cancels + waits the dashboard/index/EDB threads


def test_delete_active_project_closes_then_removes(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "active-gone", Target(ip="10.3.3.4"))
    window._set_profile(prof)  # becomes the active, edit-locked profile
    window._on_delete_requested([str(prof.directory)])
    assert not prof.directory.exists()
    assert window._profile is None  # the open project was closed before removal
    window.close()  # closeEvent cancels + waits the dashboard/index/EDB threads


def test_delete_refuses_project_locked_by_another_live_instance(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    # defect regression: a project open read-only here while ANOTHER live instance holds the edit
    # lock must never be deleted out from under that other instance — even though it is "active".
    from oscprecon.workspace import locks

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "held-elsewhere", Target(ip="10.3.3.5"))
    prof.read_only = True
    window._profile = prof  # simulate: opened read-only because the lock is held by window A

    foreign = locks.LockInfo(
        pid=999_999, hostname="other-host", app_version="1", started_at="2026-01-01T00:00:00Z"
    )
    monkeypatch.setattr(locks, "read_lock", lambda directory: (foreign, False))
    monkeypatch.setattr(locks, "is_stale", lambda info: False)  # the other instance is alive

    window._on_delete_requested([str(prof.directory)])
    assert prof.directory.is_dir()  # refused — the other instance's project is untouched
    window.close()  # closeEvent cancels + waits the dashboard/index/EDB threads


# ---- pivot topology (Edit → Add Pivoted Network) ---------------------------------------------


def test_add_pivot_network_dialog_parses_and_returns_hosts(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    from oscprecon.gui.dialogs.pivot_network import AddPivotNetworkDialog

    dialog = AddPivotNetworkDialog(["10.10.10.5", "10.10.5.23"])
    qtbot.addWidget(dialog)
    dialog._pivot_source.setCurrentText("10.10.10.5")
    dialog._text.setPlainText(
        "Nmap scan report for 10.10.5.40\n445/tcp open microsoft-ds Windows Server 2019\n"
    )
    dialog._on_accept()
    hosts = dialog.hosts()
    assert [h.ip for h in hosts] == ["10.10.5.40"]
    assert hosts[0].pivot_source == "10.10.10.5"  # picked source is stamped on the hosts


def test_add_pivot_network_wires_into_profile_and_graph(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    from PySide6.QtWidgets import QDialog

    from oscprecon.gui.dialogs.pivot_network import AddPivotNetworkDialog
    from oscprecon.models import DiscoveredHost

    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(config.workspace_root(), "ctf", Target(ip="10.10.10.5")))

    def fake_exec(self: AddPivotNetworkDialog) -> int:
        self._hosts = [DiscoveredHost(ip="10.10.5.23", pivot_source="10.10.10.5")]
        return int(QDialog.DialogCode.Accepted)

    monkeypatch.setattr(AddPivotNetworkDialog, "exec", fake_exec)
    window._on_add_pivot_network()
    assert window._profile is not None
    assert [h.ip for h in window._profile.discovered_hosts] == ["10.10.5.23"]
    # persisted to disk too
    reloaded = Profile.load(window._profile.directory)
    assert [h.ip for h in reloaded.discovered_hosts] == ["10.10.5.23"]
    window.close()
