from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon.gui.main_window import MainWindow, NewProfileDialog
from oscprecon.models import Target
from oscprecon.profile import Profile


def test_main_window_constructs(qtbot: QtBot) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    assert window.windowTitle() == "Nabu"
    assert window._run_button.isEnabled() is False


def test_status_footer_reflects_profile(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    assert window._status_profile.text() == "profile: no profile loaded"
    assert "workspace:" in window._status_workspace.text()
    window._set_profile(Profile.create(tmp_path, "htb-active", Target(ip="10.10.10.100")))
    assert window._status_profile.text() == "profile: htb-active"


def test_new_profile_dialog_values(qtbot: QtBot) -> None:
    dialog = NewProfileDialog()
    qtbot.addWidget(dialog)
    dialog._name.setText("  htb-active  ")
    dialog._ip.setText(" 10.10.10.100 ")
    assert dialog.values() == ("htb-active", "10.10.10.100", "")


def test_run_button_menu_offers_scan_options(qtbot: QtBot) -> None:
    from oscprecon import config

    window = MainWindow()
    qtbot.addWidget(window)
    menu = window._run_button.menu()
    assert menu is not None
    texts = [a.text().lower() for a in menu.actions() if a.text()]
    # every scan profile is offered, plus a custom/surgical option
    for profile in config.SCAN_PROFILES:
        assert any(profile in t for t in texts), profile
    assert any("custom" in t for t in texts)
    # the main click runs a QUICK scan (fast) — never the heavy full battery by surprise
    assert window._run_button.accessibleName() == "Run quick recon (menu for profiles/custom)"
