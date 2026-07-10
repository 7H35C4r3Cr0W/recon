from pytestqt.qtbot import QtBot

from oscprecon.gui.main_window import MainWindow, NewProfileDialog


def test_main_window_constructs(qtbot: QtBot) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    assert window.windowTitle() == "oscp-recon"
    assert window._run_button.isEnabled() is False


def test_new_profile_dialog_values(qtbot: QtBot) -> None:
    dialog = NewProfileDialog()
    qtbot.addWidget(dialog)
    dialog._name.setText("  htb-active  ")
    dialog._ip.setText(" 10.10.10.100 ")
    assert dialog.values() == ("htb-active", "10.10.10.100")
