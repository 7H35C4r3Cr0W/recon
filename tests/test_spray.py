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


def test_clean_spray_artifacts_removes_only_generated_lists(tmp_path: Path) -> None:
    spray_dir = tmp_path / "spray"
    spray_dir.mkdir()
    (spray_dir / "users.txt").write_text("administrator\n", encoding="utf-8")
    (spray_dir / "passwords.txt").write_text("Winter2024\n", encoding="utf-8")
    (spray_dir / "smb.txt").write_text("[+] evidence line\n", encoding="utf-8")  # OUTPUT — keep
    (tmp_path / "creds.json").write_text('{"entries":[]}', encoding="utf-8")  # store — keep
    wordlist = tmp_path / "my-wordlist.txt"
    wordlist.write_text("word1\nword2\n", encoding="utf-8")  # user-owned — keep

    removed = spray.clean_spray_artifacts(tmp_path)
    assert set(removed) == {"users.txt", "passwords.txt"}
    assert not (spray_dir / "users.txt").exists() and not (spray_dir / "passwords.txt").exists()
    assert (spray_dir / "smb.txt").exists()  # spray output evidence retained
    assert (tmp_path / "creds.json").exists()  # credential store untouched
    assert wordlist.exists()  # user wordlist never touched


def test_clean_spray_artifacts_is_a_safe_noop_when_absent(tmp_path: Path) -> None:
    assert spray.clean_spray_artifacts(tmp_path) == []  # nothing to remove, no error


def test_parse_spray_success_is_service_specific_and_vault_anchored() -> None:
    candidates = [("administrator", "Winter2024"), ("bob", "hunter2")]
    nxc = (
        "SMB 10.0.0.1 445 DC [+] corp.local\\administrator:Winter2024 (Pwn3d!)\n"
        "SMB 10.0.0.1 445 DC [-] corp.local\\bob:hunter2 STATUS_LOGON_FAILURE"
    )
    assert spray.parse_spray_success("smb", nxc, candidates) == [("administrator", "Winter2024")]
    hydra = "[22][ssh] host: 10.0.0.1   login: bob   password: hunter2"
    assert spray.parse_spray_success("ssh", hydra, candidates) == [("bob", "hunter2")]


def test_parse_spray_success_rejects_generic_success_word() -> None:
    candidates = [("admin", "pw")]
    # a bare "success" mention is NOT proof — only the service-specific marker counts
    assert spray.parse_spray_success("smb", "operation success for admin pw", candidates) == []
    assert spray.parse_spray_success("smb", "", candidates) == []
