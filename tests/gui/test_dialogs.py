"""Dialogs were extracted from main_window into oscprecon.gui.dialogs; prove they import from the
new location (and stay re-exported from main_window) and validate their returned values."""

from pytestqt.qtbot import QtBot

from oscprecon.gui import main_window as mw
from oscprecon.gui.dialogs import AddCredentialDialog, NewProfileDialog


def test_dialogs_reexported_from_main_window() -> None:
    assert mw.NewProfileDialog is NewProfileDialog
    assert mw.AddCredentialDialog is AddCredentialDialog


def test_new_profile_returns_trimmed_values(qtbot: QtBot) -> None:
    dialog = NewProfileDialog()
    qtbot.addWidget(dialog)
    dialog._name.setText("  htb-active  ")
    dialog._ip.setText(" 10.10.10.5 ")
    dialog._hostname.setText("  active.htb ")
    assert dialog.values() == ("htb-active", "10.10.10.5", "active.htb")


def test_new_profile_empty_values(qtbot: QtBot) -> None:
    dialog = NewProfileDialog()
    qtbot.addWidget(dialog)
    assert dialog.values() == ("", "", "")  # caller (MainWindow._on_new) rejects empties


def test_credential_dialog_builds_credential(qtbot: QtBot) -> None:
    dialog = AddCredentialDialog()
    qtbot.addWidget(dialog)
    dialog._username.setText(" svc_sql ")
    dialog._secret.setText("Ticketmaster1968")
    dialog._domain.setText("active.htb")
    cred = dialog.credential()
    assert cred is not None
    assert cred.username == "svc_sql"
    assert cred.domain == "active.htb"
    assert cred.source == "manual"  # default when the source field is blank


def test_credential_dialog_requires_username_and_secret(qtbot: QtBot) -> None:
    dialog = AddCredentialDialog()
    qtbot.addWidget(dialog)
    dialog._username.setText("only-user")
    assert dialog.credential() is None  # no secret
    dialog._username.setText("")
    dialog._secret.setText("only-secret")
    assert dialog.credential() is None  # no username


def test_credential_secret_field_is_masked(qtbot: QtBot) -> None:
    from PySide6.QtWidgets import QLineEdit

    dialog = AddCredentialDialog()
    qtbot.addWidget(dialog)
    assert (
        dialog._secret.echoMode() == QLineEdit.EchoMode.Password
    )  # secret never shown in the clear
