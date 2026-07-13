from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon.gui.main_window import MainWindow
from oscprecon.models import Credential, Target
from oscprecon.profile import Profile


def test_record_spray_success_updates_originating_project_add_only(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.5"))
    profile.add_credential(
        Credential(username="administrator", secret="Winter2024", source="manual")
    )
    profile.add_credential(Credential(username="svc", secret="Summer2024", source="manual"))
    window._set_profile(profile)

    spray_dir = profile.directory / "spray"
    spray_dir.mkdir(parents=True, exist_ok=True)
    output = spray_dir / "smb.txt"
    output.write_text(
        "SMB 10.10.10.5 445 DC [+] corp\\administrator:Winter2024 (Pwn3d!)\n", encoding="utf-8"
    )

    window._record_spray_success(profile, "smb", output)

    reloaded = profile.credentials()
    assert len(reloaded) == 2  # a successful spray never removes a credential
    admin = next(c for c in reloaded if c.username == "administrator")
    assert admin.secret == "Winter2024"  # secret preserved
    assert "spray-confirmed:smb" in admin.tested_against  # confirmation recorded (add-only)
    svc = next(c for c in reloaded if c.username == "svc")
    assert svc.tested_against == []  # unrelated cred untouched


def test_spray_done_cleans_input_lists_only_after_the_last_worker(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    profile = Profile.create(tmp_path, "box", Target(ip="10.10.10.5"))
    profile.add_credential(Credential(username="a", secret="b", source="manual"))
    window._set_profile(profile)

    spray_dir = profile.directory / "spray"
    spray_dir.mkdir(parents=True, exist_ok=True)
    (spray_dir / "users.txt").write_text("a\n", encoding="utf-8")
    (spray_dir / "passwords.txt").write_text("b\n", encoding="utf-8")
    (spray_dir / "smb.txt").write_text("out\n", encoding="utf-8")

    window._spray_pending = 2  # two sprays launched
    window._spray_done(0, profile, "smb", spray_dir / "smb.txt")
    assert (spray_dir / "users.txt").exists()  # not yet — another spray still running
    window._spray_done(0, profile, "winrm", spray_dir / "winrm.txt")
    assert not (spray_dir / "users.txt").exists()  # last worker -> input lists removed
    assert not (spray_dir / "passwords.txt").exists()
    assert profile.creds_path.exists() or not profile.credentials()  # store never touched
    assert [c.username for c in profile.credentials()] == ["a"]  # credential intact
