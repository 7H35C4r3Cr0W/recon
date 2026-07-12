from pathlib import Path

import pytest
from PySide6.QtWidgets import QFileDialog, QMessageBox
from pytestqt.qtbot import QtBot

from oscprecon.gui.main_window import MainWindow
from oscprecon.models import Credential, DiscoveredService, Proto, Target
from oscprecon.profile import Profile


def test_export_vault_action_writes_snapshot(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(tmp_path / "ws", "htb-active", Target(ip="10.10.10.100"))
    prof.set_services(
        [DiscoveredService(port=445, proto=Proto.TCP, service="microsoft-ds", discovered_at="")]
    )
    prof.add_credential(Credential(username="svc", secret="Ticketmaster1968", source="smb"))
    window._set_profile(prof)

    dest = tmp_path / "vault"
    monkeypatch.setattr(
        QFileDialog, "getExistingDirectory", staticmethod(lambda *a, **k: str(dest))
    )
    monkeypatch.setattr(QMessageBox, "information", staticmethod(lambda *a, **k: None))

    window._on_export_vault()

    out = dest / "htb-active"
    assert (out / "index.md").exists()
    assert (out / "services" / "445-tcp-microsoft-ds.md").exists()
    cred_md = next((out / "credentials").glob("*.md")).read_text(encoding="utf-8")
    assert "Ticketmaster1968" not in cred_md  # secret redacted through the GUI path too


def test_export_vault_action_without_profile_warns(
    qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    calls: list[str] = []
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: calls.append("warn")))
    # no profile loaded -> a dialog should never open; a warning fires instead
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        staticmethod(lambda *a, **k: pytest.fail("dialog opened without a profile")),
    )
    window._on_export_vault()
    assert calls == ["warn"]
