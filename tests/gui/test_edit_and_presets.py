from pathlib import Path

import pytest
from PySide6.QtWidgets import QDialog, QMessageBox
from pytestqt.qtbot import QtBot

from oscprecon import config
from oscprecon.alive import AliveResult
from oscprecon.gui.dialogs import NewProfileDialog, ScanPresetsDialog
from oscprecon.gui.main_window import _SCAN_PRESETS, MainWindow
from oscprecon.gui.widgets.exploit_panel import ExploitPanel
from oscprecon.gui.workers import CustomScanWorker, NmapWorker, PingWorker
from oscprecon.manual_commands import load_manual_commands
from oscprecon.models import Target
from oscprecon.profile import Profile


def _click_role(role: QMessageBox.ButtonRole) -> object:
    # a fake QMessageBox.exec that "clicks" the button of the given role, so headless tests can
    # drive the pre-flight confirm dialog (its result is read via clickedButton()).
    def _exec(self: QMessageBox) -> int:
        for button in self.buttons():
            if self.buttonRole(button) == role:
                button.click()
                return 0
        return 0

    return _exec


def _no_preflight() -> None:
    prefs = config.load_prefs()
    prefs["preflight_ping"] = "false"
    config.save_prefs(prefs)


# --- Edit-project dialog + handler ----------------------------------------------------------------


def test_new_project_over_existing_name_is_blocked_not_wiped(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    # regression: creating a New Project whose name matches an existing one must NOT overwrite/wipe
    # that project's profile.json — it must warn and leave the existing project untouched.
    from oscprecon.models import DiscoveredService, Proto

    window = MainWindow()
    qtbot.addWidget(window)
    existing = Profile.create(config.workspace_root(), "dup", Target(ip="10.10.10.5"))
    existing.set_services([DiscoveredService(port=445, proto=Proto.TCP, service="smb")])
    existing.save()

    def fake_exec(self: NewProfileDialog) -> int:
        self._name.setText("dup")  # same name, different target
        self._ip.setText("10.10.10.9")
        return int(QDialog.DialogCode.Accepted)

    monkeypatch.setattr(NewProfileDialog, "exec", fake_exec)
    warned: list[object] = []
    monkeypatch.setattr(
        "oscprecon.gui.main_window.QMessageBox.warning", lambda *a, **k: warned.append(a)
    )
    window._on_new()

    assert warned  # the "already exists" warning fired
    reloaded = Profile.load(config.workspace_root() / "dup")
    assert reloaded.target.ip == "10.10.10.5"  # original target preserved
    assert [s.port for s in reloaded.discovered_services] == [445]  # services NOT wiped


def test_new_profile_dialog_edit_mode_prefills(qtbot: QtBot) -> None:
    dialog = NewProfileDialog(
        title="Edit Project", name="mybox", ip="10.1.1.1", hostname="a.htb", edit=True
    )
    qtbot.addWidget(dialog)
    assert dialog.values() == ("mybox", "10.1.1.1", "a.htb")


def test_edit_project_renames_folder_and_retargets(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(tmp_path, "orig", Target(ip="10.10.10.5")))

    def fake_exec(self: NewProfileDialog) -> int:
        self._name.setText("renamed")
        self._ip.setText("10.10.10.9")
        self._hostname.setText("box.htb")
        return int(QDialog.DialogCode.Accepted)

    monkeypatch.setattr(NewProfileDialog, "exec", fake_exec)
    window._on_edit_project()

    assert window._profile is not None
    assert window._profile.profile_name == "renamed"
    assert window._profile.target.ip == "10.10.10.9"
    assert window._profile.target.hostname == "box.htb"
    assert (tmp_path / "renamed").is_dir()
    assert not (tmp_path / "orig").exists()
    # the lock moved with the folder and we still hold it (not dropped to read-only)
    assert window._profile.read_only is False
    assert window._locked_dir == tmp_path / "renamed"


def test_edit_project_to_range_project_clears_stale_discovery(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from oscprecon.models import DiscoveredService, Proto

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5", hostname="box.htb"))
    prof.set_services([DiscoveredService(port=80, proto=Proto.TCP, service="http")])
    prof.save()
    window._set_profile(prof)

    def fake_exec(self: NewProfileDialog) -> int:
        self._ip.setText("10.10.5.0/24")
        return int(QDialog.DialogCode.Accepted)

    monkeypatch.setattr(NewProfileDialog, "exec", fake_exec)
    window._on_edit_project()

    assert window._profile is not None
    assert window._profile.target.is_range is True
    assert window._profile.target.hostname is None  # dropped for a network
    # a host->/24 flip clears single-host discovery that no longer belongs to the network target
    assert window._profile.discovered_services == []


def test_set_profile_adopts_our_own_lock(qtbot: QtBot, tmp_path: Path) -> None:
    # a rename moves the .lock with the folder; if bookkeeping points elsewhere, _set_profile must
    # ADOPT our own live lock rather than collide with it and wrongly fall back to read-only.
    from oscprecon.workspace import locks

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(tmp_path, "p", Target(ip="10.10.10.5"))
    locks.acquire(prof.directory)  # OUR lock (current pid + host) sits in the folder
    window._locked_dir = tmp_path / "stale-elsewhere"  # bookkeeping points at the wrong dir
    window._set_profile(prof)
    assert window._profile is not None
    assert window._profile.read_only is False  # adopted our own lock, not read-only
    assert window._locked_dir == prof.directory


# --- Scan-presets chooser -------------------------------------------------------------------------


def test_scan_presets_dialog_fills_and_returns_mode(qtbot: QtBot) -> None:
    presets = load_manual_commands(_SCAN_PRESETS)
    assert len(presets) >= 15  # "way more" situational options
    dialog = ScanPresetsDialog(presets, "10.10.10.5")
    qtbot.addWidget(dialog)
    assert "10.10.10.5" in dialog.command()  # first preset filled with the target
    dialog._finish("load")
    assert dialog.mode() == "load"


# --- Exploitation-tab collapsible list ------------------------------------------------------------


def test_exploit_panel_list_toggle(qtbot: QtBot) -> None:
    panel = ExploitPanel("dark")
    qtbot.addWidget(panel)
    assert panel._list_collapsed is False
    panel._toggle_list()
    assert panel._list_collapsed is True
    assert panel._tree.isHidden() is True
    panel._toggle_list()
    assert panel._list_collapsed is False
    assert panel._tree.isHidden() is False


# --- Recon launch flow (preflight / range) --------------------------------------------------------


def test_start_recon_preflight_launches_ping_worker(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefs = config.load_prefs()
    prefs["preflight_ping"] = "true"
    config.save_prefs(prefs)
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(tmp_path, "b", Target(ip="10.10.10.5")))
    captured: dict[str, object] = {}
    monkeypatch.setattr(window, "_start", lambda worker, *a, **k: captured.update(worker=worker))
    window._start_recon("default")
    assert isinstance(captured["worker"], PingWorker)


def test_range_project_runs_a_network_scan(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_preflight()
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(tmp_path, "net", Target(ip="10.10.5.0/24")))
    captured: dict[str, object] = {}
    monkeypatch.setattr(window, "_start", lambda worker, *a, **k: captured.update(worker=worker))
    window._start_recon("default")
    assert isinstance(captured["worker"], CustomScanWorker)


@pytest.mark.parametrize(
    ("hosts", "role", "expected"),
    [
        (["10.10.10.5"], QMessageBox.ButtonRole.AcceptRole, NmapWorker),  # up + Start recon
        ([], QMessageBox.ButtonRole.AcceptRole, NmapWorker),  # down + Scan anyway
        (["10.10.10.5"], QMessageBox.ButtonRole.RejectRole, type(None)),  # Cancel -> nothing
    ],
)
def test_preflight_confirm_paths(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    hosts: list[str],
    role: QMessageBox.ButtonRole,
    expected: type,
) -> None:
    monkeypatch.setattr(QMessageBox, "exec", _click_role(role))
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(tmp_path, "b", Target(ip="10.10.10.5")))
    captured: dict[str, object] = {}
    monkeypatch.setattr(window, "_start", lambda worker, *a, **k: captured.update(worker=worker))
    window._preflight_done(AliveResult(hosts=hosts), "default")
    assert isinstance(captured.get("worker"), expected)


def test_preflight_range_confirm_runs_network_scan(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(QMessageBox, "exec", _click_role(QMessageBox.ButtonRole.AcceptRole))
    window = MainWindow()
    qtbot.addWidget(window)
    window._set_profile(Profile.create(tmp_path, "net", Target(ip="10.10.5.0/24")))
    captured: dict[str, object] = {}
    monkeypatch.setattr(window, "_start", lambda worker, *a, **k: captured.update(worker=worker))
    window._preflight_done(AliveResult(hosts=["10.10.5.5", "10.10.5.10"]), "default")
    assert isinstance(captured.get("worker"), CustomScanWorker)
