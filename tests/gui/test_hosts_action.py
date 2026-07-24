from pathlib import Path

import pytest
from PySide6.QtWidgets import QInputDialog, QMessageBox
from pytestqt.qtbot import QtBot

from oscprecon import config
from oscprecon import hosts as hosts_mod
from oscprecon.gui import main_window as mw
from oscprecon.gui.main_window import MainWindow
from oscprecon.models import Target
from oscprecon.profile import Profile


def test_add_hosts_entry_writes_via_handler(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Edit -> Add Host to /etc/hosts: the operator confirms an "IP vhost" entry and it is written
    # (idempotently). We redirect add_entry at the default path to a temp file so the test never
    # touches the real /etc/hosts, but the real merge logic runs.
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(
        config.workspace_root(), "box", Target(ip="10.10.10.5", hostname="bedside.htb")
    )
    window._set_profile(prof)

    hf = tmp_path / "hosts"
    hf.write_text("127.0.0.1\tlocalhost\n")
    monkeypatch.setattr(
        QInputDialog, "getText", lambda *a, **k: ("10.10.10.5 research.bedside.htb", True)
    )
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: QMessageBox.StandardButton.Ok)
    # capture the real add_entry BEFORE patching (mw.hosts and hosts_mod are the same module object)
    real_add = hosts_mod.add_entry
    monkeypatch.setattr(mw.hosts, "add_entry", lambda ip, names: real_add(ip, names, hf))

    window._on_add_hosts_entry()
    assert "10.10.10.5\tresearch.bedside.htb" in hf.read_text()


def test_add_hosts_entry_copies_sudo_when_not_root(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    # when Nabu can't write /etc/hosts (not root), the handler copies the sudo command instead.
    from PySide6.QtGui import QGuiApplication

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(config.workspace_root(), "box2", Target(ip="10.10.10.6"))
    window._set_profile(prof)

    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("10.10.10.6 x.htb", True))
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: QMessageBox.StandardButton.Ok)

    def _boom(_ip: str, _names: list[str]) -> None:
        raise PermissionError("read-only")

    monkeypatch.setattr(mw.hosts, "add_entry", _boom)

    window._on_add_hosts_entry()
    clip = QGuiApplication.clipboard()
    assert clip is not None
    assert "sudo tee -a /etc/hosts" in clip.text()
