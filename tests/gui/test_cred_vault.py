from pathlib import Path

import pytest
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QDialog
from pytestqt.qtbot import QtBot

from oscprecon.gui.dialogs import cred_vault
from oscprecon.gui.dialogs.cred_vault import CredentialVaultDialog
from oscprecon.models import Credential, Target
from oscprecon.profile import Profile


def _profile(tmp_path: Path) -> Profile:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    prof.add_credential(Credential(username="alice", secret="secret1"))
    prof.add_credential(Credential(username="bob", secret="hunter2", domain="corp"))
    return prof


def _all_cell_text(dialog: CredentialVaultDialog) -> str:
    table = dialog._table
    texts = []
    for r in range(table.rowCount()):
        for c in range(table.columnCount()):
            item = table.item(r, c)
            if item is not None:
                texts.append(item.text())
    return " ".join(texts)


def test_vault_table_shows_masked_secrets(qtbot: QtBot, tmp_path: Path) -> None:
    d = CredentialVaultDialog(_profile(tmp_path))
    qtbot.addWidget(d)
    assert d._table.rowCount() == 2
    joined = _all_cell_text(d)
    assert "alice" in joined and "bob" in joined and "corp" in joined
    assert "secret1" not in joined and "hunter2" not in joined  # plaintext never shown
    assert "redacted" in joined


def test_vault_delete_removes_selected(qtbot: QtBot, tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    d = CredentialVaultDialog(prof)
    qtbot.addWidget(d)
    d._table.selectRow(0)
    d._on_delete()
    assert d._table.rowCount() == 1
    assert len(prof.credentials()) == 1  # persisted (durable, only explicit delete removes)


def test_vault_add_via_dialog(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    d = CredentialVaultDialog(prof)
    qtbot.addWidget(d)
    monkeypatch.setattr(
        cred_vault.AddCredentialDialog, "exec", lambda self: QDialog.DialogCode.Accepted
    )
    monkeypatch.setattr(
        cred_vault.AddCredentialDialog,
        "credential",
        lambda self: Credential(username="carol", secret="pw"),
    )
    d._on_add()
    assert d._table.rowCount() == 1 and prof.credentials()[0].username == "carol"


def test_vault_edit_replaces_selected(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prof = _profile(tmp_path)
    d = CredentialVaultDialog(prof)
    qtbot.addWidget(d)
    d._table.selectRow(0)  # alice
    monkeypatch.setattr(
        cred_vault.AddCredentialDialog, "exec", lambda self: QDialog.DialogCode.Accepted
    )
    monkeypatch.setattr(
        cred_vault.AddCredentialDialog,
        "credential",
        lambda self: Credential(username="alice", secret="rotated", source="manual"),
    )
    d._on_edit()
    users = {c.username: c for c in prof.credentials()}
    assert len(users) == 2 and users["alice"].secret == "rotated"  # updated, not duplicated


def test_vault_copy_actions_use_clipboard_never_the_ui(qtbot: QtBot, tmp_path: Path) -> None:
    d = CredentialVaultDialog(_profile(tmp_path))
    qtbot.addWidget(d)
    d._table.selectRow(1)  # bob / hunter2
    d._on_copy_username()
    assert QGuiApplication.clipboard().text() == "bob"
    copied: list[str] = []
    d.secret_copied.connect(copied.append)
    d._on_copy_secret()
    assert QGuiApplication.clipboard().text() == "hunter2"  # secret only ever on the clipboard
    assert "hunter2" not in _all_cell_text(d)  # never rendered in the table
    assert copied == ["bob"]  # audit signal carries the username only, never the secret


def test_vault_confirmed_column_reflects_spray_confirmation(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    prof.add_credential(
        Credential(username="svc", secret="x", tested_against=["spray-confirmed:smb"])
    )
    d = CredentialVaultDialog(prof)
    qtbot.addWidget(d)
    assert "smb" in _all_cell_text(d)  # confirmation surfaced in the Confirmed column


def test_vault_read_only_disables_mutation_but_not_copy(qtbot: QtBot, tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    prof.read_only = True
    d = CredentialVaultDialog(prof)
    qtbot.addWidget(d)
    assert not d._add.isEnabled() and not d._edit.isEnabled() and not d._delete.isEnabled()
    assert d._copy_user.isEnabled() and d._copy_secret.isEnabled()  # copy is read-only-safe
