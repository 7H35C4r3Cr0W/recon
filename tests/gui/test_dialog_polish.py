from pathlib import Path

from pytestqt.qtbot import QtBot

from oscprecon.gui.dialogs.cred_vault import CredentialVaultDialog
from oscprecon.gui.dialogs.credential import AddCredentialDialog
from oscprecon.gui.dialogs.spray import SprayDialog
from oscprecon.gui.theme import styles, tokens
from oscprecon.models import Credential, Target
from oscprecon.profile import Profile


def test_danger_button_uses_error_colour() -> None:
    qss = styles.danger_button(tokens.DARK)
    assert tokens.DARK.error in qss and "hover" in qss


def test_add_credential_ok_gated_on_required_fields(qtbot: QtBot) -> None:
    d = AddCredentialDialog()
    qtbot.addWidget(d)
    assert not d._ok.isEnabled()  # empty form -> Ok disabled
    d._username.setText("alice")
    assert not d._ok.isEnabled()  # username alone is not enough
    d._secret.setText("pw")
    assert d._ok.isEnabled()  # both present -> Ok enabled
    assert tokens.DARK.accent in d._ok.styleSheet()  # Ok is the primary action


def test_vault_buttons_ranked_and_selection_gated(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    prof.add_credential(Credential(username="alice", secret="s"))
    d = CredentialVaultDialog(prof)
    qtbot.addWidget(d)
    assert tokens.DARK.accent in d._add.styleSheet()  # Add is primary
    assert tokens.DARK.error in d._delete.styleSheet()  # Delete is destructive
    assert not d._edit.isEnabled() and not d._delete.isEnabled()  # no selection yet
    d._table.selectRow(0)
    assert d._edit.isEnabled() and d._delete.isEnabled() and d._copy_secret.isEnabled()


def test_spray_run_is_primary_and_gated(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    off = SprayDialog(prof, spray_enabled=False)
    qtbot.addWidget(off)
    assert tokens.DARK.accent in off._run.styleSheet()
    assert not off._run.isEnabled()  # spray mode off -> Run gated
    on = SprayDialog(prof, spray_enabled=True)
    qtbot.addWidget(on)
    assert on._run.isEnabled()
