"""Regression tests for the final chunked-review bug fixes (9 confirmed findings).

Each test names the finding it locks in so a future refactor can't silently reintroduce it.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from oscprecon import shell, spray
from oscprecon.models import Target
from oscprecon.modules.peek import has_unsafe_peek_chars, is_peekable
from oscprecon.modules.smb import is_share_peekable
from oscprecon.modules.smb.parsers import SmbEntry
from oscprecon.modules.snmp import SnmpModule
from oscprecon.profile import Profile
from oscprecon.workspace import portability
from oscprecon.workspace.portability import ProjectArchiveError

# --- #1 SMB/FTP peek: a target-controlled filename must never reach a command interpreter -------


@pytest.mark.parametrize(
    "name",
    [
        "x;get loot /tmp/pwn",  # smbclient -c command separator
        "!id",  # leading shell escape
        "`id`.txt",  # backtick
        'a"b.txt',  # quote breakout
        "a\nb.txt",  # newline
        "x|nc.txt",  # pipe
        "a&b.txt",  # background/and
    ],
)
def test_peek_rejects_command_metachar_filenames(name: str) -> None:
    assert has_unsafe_peek_chars(name)
    assert not is_peekable(name, is_dir=False, size=100)  # still listed, just not content-peeked
    assert not is_share_peekable(SmbEntry(name, False, 100))


@pytest.mark.parametrize(
    "name", ["config.php", "backup.bak", "access.log", "notes (1).txt", "web.config"]
)
def test_peek_still_allows_benign_data_files(name: str) -> None:
    assert not has_unsafe_peek_chars(name)
    assert is_peekable(name, is_dir=False, size=100)


# --- #2 netexec -H/--hashes pass-the-hash spraying gated in default recon mode ------------------


def test_netexec_multi_hash_spray_blocked() -> None:
    argv = ["netexec", "smb", "10.10.10.10", "-u", "administrator", "-H", "h1", "h2", "h3"]
    assert shell.policy_violation(argv) is not None


def test_netexec_hash_file_blocked() -> None:
    argv = ["netexec", "smb", "10.10.10.10", "-u", "admin", "-H", "hashes.txt"]
    assert shell.policy_violation(argv) is not None


def test_netexec_single_pass_the_hash_allowed() -> None:
    # Tier-2 single PtH stays allowed (one inline value, not a file) — mirrors `-p ''`.
    argv = ["netexec", "smb", "10.10.10.10", "-u", "admin", "-H", "aad3b435:5f4dcc3b"]
    assert shell.policy_violation(argv) is None


def test_netexec_hash_spray_allowed_in_spray_mode() -> None:
    argv = ["netexec", "smb", "10.10.10.10", "-u", "admin", "-H", "h1", "h2"]
    assert shell.policy_violation(argv, spray=True) is None


# --- #6 redis / mongo write & destructive verbs are not recon -----------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["redis-cli", "-h", "10.10.10.10", "FLUSHALL"],
        ["redis-cli", "-h", "10.10.10.10", "CONFIG", "SET", "dir", "/var/www"],
        ["redis-cli", "-h", "10.10.10.10", "MODULE", "LOAD", "/tmp/x.so"],
        ["redis-cli", "-h", "10.10.10.10", "SLAVEOF", "1.2.3.4", "6379"],
        ["mongo", "--host", "10.10.10.10", "--eval", "db.users.drop()"],
        ["mongosh", "--host", "10.10.10.10", "--eval", "db.eval('shellcode')"],
    ],
)
def test_nosql_write_verbs_blocked(argv: list[str]) -> None:
    assert shell.policy_violation(argv) is not None


@pytest.mark.parametrize(
    "argv",
    [
        ["redis-cli", "-h", "10.10.10.10", "INFO"],
        ["redis-cli", "-h", "10.10.10.10", "CONFIG", "GET", "dir"],
        ["redis-cli", "-h", "10.10.10.10", "MODULE", "LIST"],
        ["redis-cli", "-h", "10.10.10.10", "--scan"],
        [
            "mongosh",
            "--host",
            "10.10.10.10",
            "--quiet",
            "--eval",
            "printjson(db.runCommand({ping:1}))",
        ],
        ["mongo", "--host", "10.10.10.10", "--eval", "db.getSiblingDB('x').getCollectionNames()"],
    ],
)
def test_nosql_readonly_enum_allowed(argv: list[str]) -> None:
    assert shell.policy_violation(argv) is None


# --- #5 tar inode-bomb capped DURING enumeration, not after getmembers() materializes all -------


def test_import_rejects_too_many_members(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(portability, "_MAX_MEMBERS", 5)
    arc = tmp_path / "bomb.tar.gz"
    with tarfile.open(arc, "w:gz") as tar:
        for i in range(12):
            info = tarfile.TarInfo(f"proj/f{i}")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(ProjectArchiveError):
        portability.import_project_archive(arc, tmp_path / "ws")


# --- #8 SNMP honours a non-standard discovered port (default 161 command stays byte-identical) --

_COMMUNITY_LIST = "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt"


def test_snmp_default_port_commands_unchanged() -> None:
    module, target = SnmpModule(), Target(ip="10.10.10.10")
    disc = module.discovery_steps(target)
    walk = module.walk_step(target)
    assert disc[0].command.shell_line == f"onesixtyone -c {_COMMUNITY_LIST} 10.10.10.10"
    assert walk.command.shell_line == "snmpwalk -v2c -c public 10.10.10.10"


def test_snmp_nonstandard_port_threaded() -> None:
    module, target = SnmpModule(), Target(ip="10.10.10.10")
    disc = module.discovery_steps(target, 1161)
    walk = module.walk_step(target, port=1161)
    assert "-p 1161" in disc[0].command.shell_line  # onesixtyone
    assert "10.10.10.10:1161" in walk.command.shell_line  # snmpwalk net-snmp transport


# --- #4 profile.json / creds.json atomic write uses a UNIQUE temp (no shared fixed .tmp) --------


def test_profile_save_leaves_no_fixed_tmp_and_valid_json(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    prof.save()
    assert not (prof.directory / "profile.json.tmp").exists()  # unique temp, cleaned by os.replace
    json.loads((prof.directory / "profile.json").read_text(encoding="utf-8"))  # valid JSON


# --- #3 CLI spray output pre-created 0600 (holds the winning cred in cleartext) -----------------


def test_spray_secure_output_file_is_0600(tmp_path: Path) -> None:
    out = tmp_path / "spray" / "smb.txt"
    spray.secure_output_file(out)
    assert (out.stat().st_mode & 0o777) == 0o600
