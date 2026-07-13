from pathlib import Path

from PySide6.QtCore import QThread
from pytestqt.qtbot import QtBot

from oscprecon import audit
from oscprecon.gui.main_window import MainWindow
from oscprecon.models import Credential, Target
from oscprecon.profile import Profile


class _Dummy(QThread):
    def run(self) -> None:  # finish at once; the default QThread.run() spins an event loop forever
        return


def _actions(profile_dir: Path) -> list[str]:
    return [e["action"] for e in audit.load_entries(profile_dir)]


def test_open_and_save_are_audited(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    window._open_path(prof.directory)
    window._on_save()
    actions = _actions(prof.directory)
    assert "profile-opened" in actions
    assert "profile-saved" in actions


def test_launch_and_finish_are_audited(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    window._set_profile(prof)
    worker = _Dummy()
    window._launch(worker, "smb full")
    # the worker finishes immediately; spin the loop until finished -> _release fires
    qtbot.waitUntil(lambda: window._tasks.active_count == 0, timeout=3000)
    entries = audit.load_entries(prof.directory)
    run = next(e for e in entries if e["action"] == "run")
    assert run["details"]["label"] == "smb full"
    assert any(e["action"] == "run-finished" for e in entries)


def test_credential_audit_redacts_secret(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    window._set_profile(prof)
    # exercise the emit directly with the same fields the dialog would supply
    cred = Credential(username="svc", secret="Ticketmaster1968", source="smb")
    prof.add_credential(cred)
    window._audit_action(
        "credential-added",
        username=cred.username,
        domain=cred.domain,
        secret_type=cred.secret_type,
        source=cred.source,
    )
    text = audit.audit_path(prof.directory).read_text(encoding="utf-8")
    assert "Ticketmaster1968" not in text  # secret never passed to the trail
    entry = next(e for e in audit.load_entries(prof.directory) if e["action"] == "credential-added")
    assert entry["details"]["username"] == "svc"
    assert "secret" not in entry["details"]  # not even a redacted placeholder — never supplied


def test_live_refresh_is_audited(qtbot: QtBot, tmp_path: Path, monkeypatch) -> None:
    from oscprecon import config, references
    from oscprecon.models import DiscoveredService, Proto

    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    window._set_profile(prof)
    svc = DiscoveredService(445, Proto.TCP, "microsoft-ds")
    window._reference_pane.show_service(svc, references.match(svc))
    live = config.default_settings()
    live.hacktricks_live_enabled = True
    monkeypatch.setattr(config, "load_settings", lambda: live)
    monkeypatch.setattr(window, "_dispatch_live", lambda *a, **k: None)  # no real network fetch
    window._on_live_refresh()
    ref = next(
        e for e in audit.load_entries(prof.directory) if e["action"] == "hacktricks-live-refresh"
    )
    assert "hacktricks.wiki" in ref["details"]["url"]


def test_spray_confirmation_is_audited_without_secret(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    prof = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    prof.add_credential(Credential(username="administrator", secret="Winter2024!", source="manual"))
    window._set_profile(prof)
    spray_dir = prof.directory / "spray"
    spray_dir.mkdir(parents=True, exist_ok=True)
    out = spray_dir / "smb.txt"
    out.write_text("SMB 10.10.10.5 445 DC [+] corp\\administrator:Winter2024! (Pwn3d!)\n")
    window._record_spray_success(prof, "smb", out)
    entries = audit.load_entries(prof.directory)
    conf = next(e for e in entries if e["action"] == "spray-confirmed")
    assert conf["details"]["service"] == "smb" and conf["details"]["count"] == 1
    # the winning secret must never appear anywhere in the audit log
    assert "Winter2024!" not in (prof.directory / "audit.jsonl").read_text()
