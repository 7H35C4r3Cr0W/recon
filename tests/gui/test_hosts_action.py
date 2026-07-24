from pathlib import Path

import pytest
from PySide6.QtWidgets import QMessageBox
from pytestqt.qtbot import QtBot

from oscprecon import config
from oscprecon import hosts as hosts_mod
from oscprecon.gui import main_window as mw
from oscprecon.gui.dialogs.hosts_manager import HostsManagerDialog
from oscprecon.gui.main_window import MainWindow
from oscprecon.models import Target
from oscprecon.profile import Profile


def test_add_host_from_panel_writes(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the Exploitation tab's ＋hosts button emits (ip, hostname); the window adds it to /etc/hosts.
    # We redirect add_entry to a temp file so the test never touches the real /etc/hosts.
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(
        config.workspace_root(), "box", Target(ip="10.10.10.5", hostname="bedside.htb")
    )
    window._set_profile(prof)

    hf = tmp_path / "hosts"
    hf.write_text("127.0.0.1\tlocalhost\n")
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: QMessageBox.StandardButton.Ok)
    real_add = hosts_mod.add_entry
    monkeypatch.setattr(mw.hosts, "add_entry", lambda ip, names: real_add(ip, names, hf))

    window._on_add_host_from_panel("10.10.10.5", "research.bedside.htb")
    assert "10.10.10.5\tresearch.bedside.htb" in hf.read_text()


def test_add_host_from_panel_copies_sudo_when_not_root(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    from PySide6.QtGui import QGuiApplication

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "box2", Target(ip="10.10.10.6"))
    window._set_profile(prof)
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: QMessageBox.StandardButton.Ok)

    def _boom(_ip: str, _names: list[str]) -> None:
        raise PermissionError("read-only")

    monkeypatch.setattr(mw.hosts, "add_entry", _boom)
    window._on_add_host_from_panel("10.10.10.6", "x.htb")
    clip = QGuiApplication.clipboard()
    assert clip is not None
    assert "sudo tee -a /etc/hosts" in clip.text()


def test_edit_menu_opens_hosts_manager(qtbot: QtBot, monkeypatch: pytest.MonkeyPatch) -> None:
    # Edit -> Add Host to /etc/hosts opens the Hosts Manager (constructs it without error).
    opened: list[bool] = []
    monkeypatch.setattr(HostsManagerDialog, "exec", lambda self: opened.append(True) or 0)
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "m", Target(ip="10.10.10.5", hostname="box.htb"))
    window._set_profile(prof)
    window._on_add_hosts_entry()
    assert opened == [True]
