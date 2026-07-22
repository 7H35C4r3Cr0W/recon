import shlex
import stat
from pathlib import Path

import pytest

from oscprecon import shell, spray
from oscprecon.models import Credential


@pytest.fixture(autouse=True)
def _redaction_on(monkeypatch: pytest.MonkeyPatch) -> None:
    # These tests exercise the secret-MASKING capability. The shipping default is
    # shell.REDACT_SECRETS=False (owner policy 2026-07-22: never redact loot), so enable it
    # here to verify the masking logic still works when a build opts in.
    from oscprecon import shell

    monkeypatch.setattr(shell, "REDACT_SECRETS", True)


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


def test_make_redactor_masks_secrets_in_tool_output() -> None:
    redact = spray.make_redactor(["Password123", "pw", "Winter2024!"])
    # netexec / hydra echo the winning secret in plaintext — it must be masked before UI/logs
    nxc = "SMB 10.0.0.1 445 DC [+] corp\\administrator:Password123 (Pwn3d!)"
    out = redact(nxc)
    assert "Password123" not in out and "<redacted len=11>" in out
    hydra = "[22][ssh] host: 10.0.0.1   login: bob   password: Winter2024!"
    assert "Winter2024!" not in redact(hydra)
    assert redact("no secret here") == "no secret here"  # untouched otherwise


def test_make_redactor_longest_first_no_partial_mask() -> None:
    # a short secret that is a substring of a longer one must not partially mask the longer
    redact = spray.make_redactor(["pass", "password1"])
    assert redact("got password1 ok") == "got <redacted len=9> ok"


def test_secure_output_file_is_0600(tmp_path: Path) -> None:
    out = tmp_path / "spray" / "smb.txt"
    spray.secure_output_file(out)
    assert out.exists() and stat.S_IMODE(out.stat().st_mode) == 0o600
    # forces 0600 even if it pre-existed at a looser mode
    out.chmod(0o644)
    spray.secure_output_file(out)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_build_spray_command_preserves_nonstandard_port(tmp_path: Path) -> None:
    u, p = tmp_path / "u", tmp_path / "p"
    # hydra service on a relocated port -> -s <port>; netexec service -> --port <port>
    ssh = spray.build_spray_command("ssh", "10.0.0.1", u, p, 2222)
    assert "-s 2222" in ssh and "ssh://10.0.0.1" in ssh
    smb = spray.build_spray_command("smb", "10.0.0.1", u, p, 4445)
    assert "--port 4445" in smb
    # the standard port keeps the clean command (no override emitted)
    assert "-s " not in spray.build_spray_command("ssh", "10.0.0.1", u, p, 22)
    assert "--port" not in spray.build_spray_command("smb", "10.0.0.1", u, p, 445)
    assert "--port" not in spray.build_spray_command("smb", "10.0.0.1", u, p, None)


def test_ported_spray_command_stays_policy_gated(tmp_path: Path) -> None:
    u, p = tmp_path / "u", tmp_path / "p"
    for key, port in (("ssh", 2222), ("smb", 4445), ("ftp", 2121)):
        argv = shlex.split(spray.build_spray_command(key, "10.0.0.1", u, p, port))
        # a port'd spray is STILL blocked in the default mode and only runs in Spray mode
        assert shell.policy_violation(argv) is not None
        assert shell.policy_violation(argv, spray=True) is None


def test_discovered_port_matches_by_nmap_service_name() -> None:
    from oscprecon.models import DiscoveredService, Proto

    services = [
        DiscoveredService(2222, Proto.TCP, "ssh"),
        DiscoveredService(445, Proto.TCP, "microsoft-ds"),
        DiscoveredService(636, Proto.TCP, "ldapssl"),
    ]
    assert spray.discovered_port("ssh", services) == 2222  # relocated SSH found
    assert spray.discovered_port("smb", services) == 445  # by microsoft-ds
    assert spray.discovered_port("ldap", services) == 636
    assert spray.discovered_port("ftp", services) is None  # not discovered -> default
    assert spray.discovered_port("bogus", services) is None


def test_ftp_spray_uses_control_port_not_data_port() -> None:
    # regression: "ftp-data" (port 20) in the FTP nmap_names made discovered_port pick the DATA
    # port, so hydra sprayed :20 and silently failed. Only the control service (21) is sprayable.
    from oscprecon.models import DiscoveredService, Proto

    services = [
        DiscoveredService(20, Proto.TCP, "ftp-data"),  # listed first (ascending) — the trap
        DiscoveredService(21, Proto.TCP, "ftp"),
    ]
    assert spray.discovered_port("ftp", services) == 21
