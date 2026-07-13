import shlex
import stat
from pathlib import Path

import pytest

from oscprecon import shell, spray
from oscprecon.models import Credential


def test_build_spray_command_interpolates_and_is_gated(tmp_path: Path) -> None:
    users = tmp_path / "users.txt"
    passwords = tmp_path / "passwords.txt"
    users.write_text("admin\n", encoding="utf-8")
    passwords.write_text("Password1\n", encoding="utf-8")
    for service in spray.SPRAY_SERVICES:
        cmd = spray.build_spray_command(service.key, "10.10.10.5", users, passwords)
        assert "10.10.10.5" in cmd
        argv = shlex.split(cmd)
        # CRITICAL: a spray command is blocked in the default mode and ONLY runs in Spray mode
        assert shell.policy_violation(argv) is not None, cmd
        assert shell.policy_violation(argv, spray=True) is None, cmd


def test_unknown_service_raises() -> None:
    with pytest.raises(ValueError, match="unknown spray service"):
        spray.build_spray_command("telnet", "10.0.0.1", Path("u"), Path("p"))


def test_vault_material_distinct_users_and_password_secrets_only() -> None:
    creds = [
        Credential(username="admin", secret="P@ss", secret_type="password"),
        Credential(username="admin", secret="Other", secret_type="password"),  # dup username
        Credential(username="svc", secret="", secret_type="password"),  # empty secret dropped
        Credential(username="hashacct", secret="aad3b435", secret_type="hash"),  # not a password
    ]
    users, passwords = spray.vault_material(creds)
    assert users == ["admin", "svc", "hashacct"]  # distinct usernames, in order
    assert passwords == ["P@ss", "Other"]  # hash + empty secret excluded


def test_write_spray_lists_dedups_and_is_0600(tmp_path: Path) -> None:
    users_path, passwords_path = spray.write_spray_lists(tmp_path, ["a", "a", "b"], ["x", "x", "y"])
    assert users_path.read_text(encoding="utf-8").split() == ["a", "b"]
    assert passwords_path.read_text(encoding="utf-8").split() == ["x", "y"]
    # passwords.txt holds plaintext secrets -> 0600 like creds.json
    assert stat.S_IMODE(passwords_path.stat().st_mode) == 0o600
    assert users_path.parent.name == "spray"
