import dataclasses
from pathlib import Path

import pytest
from PySide6.QtWidgets import QDialog
from pytestqt.qtbot import QtBot

from oscprecon import config
from oscprecon.gui import main_window as mw
from oscprecon.gui.dialogs.spray import SprayDialog
from oscprecon.models import Credential, Target
from oscprecon.profile import Profile


def _enable_spray() -> None:
    config.save_settings(dataclasses.replace(config.load_settings(), spray_enabled=True))


def test_run_button_gated_on_spray_mode(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(config.workspace_root(), "b", Target(ip="10.0.0.1"))
    off = SprayDialog(prof, spray_enabled=False)
    qtbot.addWidget(off)
    assert not off._run.isEnabled()  # OFF -> can't run
    on = SprayDialog(prof, spray_enabled=True)
    qtbot.addWidget(on)
    assert on._run.isEnabled()


def test_preview_builds_selected_service_commands(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(config.workspace_root(), "b", Target(ip="10.0.0.1"))
    d = SprayDialog(prof, spray_enabled=True)
    qtbot.addWidget(d)
    d._checks["smb"].setChecked(True)
    d._checks["ssh"].setChecked(True)
    preview = d._preview.toPlainText()
    assert (
        "netexec smb 10.0.0.1" in preview and "hydra -L" in preview and "ssh://10.0.0.1" in preview
    )
    assert set(d.selected_services()) == {"smb", "ssh"}


def test_per_credential_selection(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(config.workspace_root(), "b", Target(ip="10.0.0.1"))
    prof.add_credential(Credential(username="admin", secret="Winter2024", source="t"))
    prof.add_credential(Credential(username="svc", secret="P@ss", source="t"))
    d = SprayDialog(prof, spray_enabled=True)
    qtbot.addWidget(d)
    # all vault creds are selected by default
    assert set(d.selected_users()) == {"admin", "svc"}
    assert set(d.selected_passwords()) == {"Winter2024", "P@ss"}
    # the on-screen password labels are masked, not the plaintext secret
    labels = [d._pass_list.item(i).text() for i in range(d._pass_list.count())]
    assert all("•" in lab and "Winter2024" not in lab and "P@ss" not in lab for lab in labels)
    # unticking a username narrows the spray set
    from PySide6.QtCore import Qt

    for i in range(d._users_list.count()):
        if d._users_list.item(i).text() == "svc":
            d._users_list.item(i).setCheckState(Qt.CheckState.Unchecked)
    assert d.selected_users() == ["admin"]
    assert "1 username(s) × 2 password(s) selected" in d._preview.toPlainText()


def test_preview_uses_discovered_nonstandard_port(qtbot: QtBot, tmp_path: Path) -> None:
    from oscprecon.models import DiscoveredService, Proto

    prof = Profile.create(config.workspace_root(), "b", Target(ip="10.0.0.1"))
    prof.discovered_services = [DiscoveredService(2222, Proto.TCP, "ssh")]  # SSH relocated
    d = SprayDialog(prof, spray_enabled=True)
    qtbot.addWidget(d)
    d._checks["ssh"].setChecked(True)
    preview = d._preview.toPlainText()
    assert "-s 2222" in preview and "ssh://10.0.0.1" in preview  # sprays the discovered port


def test_spray_launches_gated_worker_when_enabled(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = mw.MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "b", Target(ip="10.0.0.1"))
    prof.add_credential(Credential(username="admin", secret="Password1"))
    window._set_profile(prof)
    _enable_spray()
    monkeypatch.setattr(mw.SprayDialog, "exec", lambda self: QDialog.DialogCode.Accepted)
    monkeypatch.setattr(mw.SprayDialog, "selected_services", lambda self: ["smb"])
    captured: dict[str, object] = {}
    monkeypatch.setattr(window, "_start", lambda worker, *a, **k: captured.update(worker=worker))
    window._on_credential_spray()
    worker = captured["worker"]
    assert worker._spray is True  # type: ignore[attr-defined]  — the gated flag is set
    assert "netexec smb 10.0.0.1" in worker._shell_line  # type: ignore[attr-defined]
    assert (prof.directory / "spray" / "passwords.txt").exists()  # spray lists written


def test_spray_blocked_when_setting_off(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = mw.MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "b", Target(ip="10.0.0.1"))
    prof.add_credential(Credential(username="admin", secret="Password1"))
    window._set_profile(prof)
    # spray mode is OFF (default). Even if a stubbed dialog accepts, the config re-check must block.
    monkeypatch.setattr(mw.SprayDialog, "exec", lambda self: QDialog.DialogCode.Accepted)
    monkeypatch.setattr(mw.SprayDialog, "selected_services", lambda self: ["smb"])
    launched: list[object] = []
    monkeypatch.setattr(window, "_start", lambda worker, *a, **k: launched.append(worker))
    window._on_credential_spray()
    assert launched == []  # nothing launched — the gate held
