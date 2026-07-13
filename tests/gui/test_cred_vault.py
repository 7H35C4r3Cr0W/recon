from pathlib import Path

import pytest
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


def test_vault_lists_with_redacted_secrets(qtbot: QtBot, tmp_path: Path) -> None:
    d = CredentialVaultDialog(_profile(tmp_path))
    qtbot.addWidget(d)
    assert d._list.count() == 2
    labels = [d._list.item(i).text() for i in range(d._list.count())]
    joined = " ".join(labels)
    assert "alice" in joined and "bob@corp" in joined
    assert "secret1" not in joined and "hunter2" not in joined  # secrets redacted
    assert "redacted" in joined


def test_vault_delete_removes_entry(qtbot: QtBot, tmp_path: Path) -> None:
    prof = _profile(tmp_path)
    d = CredentialVaultDialog(prof)
    qtbot.addWidget(d)
    d._list.setCurrentRow(0)
    d._on_delete()
    assert d._list.count() == 1
    assert len(prof.credentials()) == 1  # persisted


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
    assert d._list.count() == 1
    assert prof.credentials()[0].username == "carol"


def test_vault_read_only_disables_edit(qtbot: QtBot, tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    prof.read_only = True
    d = CredentialVaultDialog(prof)
    qtbot.addWidget(d)
    assert not d._delete.isEnabled()
