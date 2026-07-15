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
