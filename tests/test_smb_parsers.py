from pathlib import Path

from oscprecon.modules.smb.parsers import (
    netexec_auth_ok,
    parse_netexec_passpol,
    parse_netexec_ridbrute,
    parse_netexec_shares,
    parse_netexec_users,
    parse_rpcclient_users,
    parse_smb_tool,
    parse_smbclient_shares,
    readable_shares,
)

FIX = Path(__file__).parent / "fixtures" / "smb"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_netexec_shares_and_signing_and_auth() -> None:
    text = _read("netexec-shares.txt")
    findings = parse_netexec_shares(text)
    kinds = {(f.kind, f.value) for f in findings}
    assert ("signing", "enabled") in kinds
    assert ("auth", "authenticated") in kinds
    shares = {f.value: f.detail for f in findings if f.kind == "share"}
    assert set(shares) == {"ADMIN$", "C$", "IPC$", "Replication"}
    assert shares["IPC$"] == "READ"
    assert shares["ADMIN$"] == ""  # remark words are not treated as permissions
    assert netexec_auth_ok(text) is True
    assert set(readable_shares(findings)) == {"IPC$", "Replication"}


def test_netexec_auth_failure() -> None:
    assert (
        netexec_auth_ok("SMB  10.0.0.1  445  H  [-] domain\\user:pass STATUS_LOGON_FAILURE")
        is False
    )


def test_netexec_share_read_write_and_multiword() -> None:
    # netexec 1.4.0 emits perms as one comma-joined token; share names may contain spaces.
    text = (
        "SMB  10.0.0.1  445  DC  Share           Permissions     Remark\n"
        "SMB  10.0.0.1  445  DC  -----           -----------     ------\n"
        "SMB  10.0.0.1  445  DC  Data            READ,WRITE      user data\n"
        "SMB  10.0.0.1  445  DC  Team Share      READ            dept files\n"
    )
    shares = {f.value: f.detail for f in parse_netexec_shares(text) if f.kind == "share"}
    assert shares["Data"] == "READ,WRITE"  # both perms survive (was parsed as no-access)
    assert shares["Team Share"] == "READ"  # multi-word name intact (was truncated to "Team")
    assert set(readable_shares(parse_netexec_shares(text))) == {"Data", "Team Share"}


def test_netexec_users() -> None:
    # netexec 1.4.0 columnar --users output (no domain prefix)
    users = {f.value for f in parse_netexec_users(_read("netexec-users.txt"))}
    assert users == {"Administrator", "Guest", "svc_tgs"}


def test_netexec_users_legacy_domain_prefix() -> None:
    # older CME-style "DOMAIN\\user" output still parses via the backslash fallback
    text = "SMB  10.0.0.1  445  DC  active.htb\\svc_old   badpwdcount: 0\n"
    assert {f.value for f in parse_netexec_users(text)} == {"svc_old"}


def test_netexec_ridbrute_only_users() -> None:
    users = {f.value for f in parse_netexec_ridbrute(_read("netexec-ridbrute.txt"))}
    assert users == {"Administrator", "Guest", "svc_account"}  # the SidTypeGroup is excluded


def test_netexec_passpol() -> None:
    policy = {f.value: f.detail for f in parse_netexec_passpol(_read("netexec-passpol.txt"))}
    assert policy["Minimum password length"] == "7"
    assert policy["Account Lockout Threshold"] == "None"


def test_smbclient_shares() -> None:
    shares = {f.value for f in parse_smbclient_shares(_read("smbclient-L.txt"))}
    assert shares == {"ADMIN$", "C$", "IPC$", "Replication"}


def test_rpcclient_users() -> None:
    users = {f.value for f in parse_rpcclient_users(_read("rpcclient-users.txt"))}
    assert users == {"Administrator", "Guest", "svc_account"}


def test_dispatch_and_garbage() -> None:
    assert parse_smb_tool("unknown", "x") == []
    assert parse_smb_tool("netexec-shares", _read("netexec-shares.txt"))
    assert parse_netexec_users("no users here") == []


def test_parse_smbclient_ls_extracts_files_dirs_sizes() -> None:
    from oscprecon.modules.smb.parsers import parse_smbclient_ls

    text = (
        "  .                                   D        0  Mon Jan  1 12:00:00 2024\n"
        "  ..                                  D        0  Mon Jan  1 12:00:00 2024\n"
        "  web.config                          A     1024  Tue Feb  2 09:30:00 2024\n"
        "  Program Files                       D        0  Wed Mar  3 10:00:00 2024\n"
        "  huge.iso                            A  99999999  Thu Apr  4 11:00:00 2024\n"
        "\n\t\t9204224 blocks of size 1024. 2000000 blocks available\n"
    )
    entries = {e.name: e for e in parse_smbclient_ls(text)}
    assert "." not in entries and ".." not in entries  # skipped
    assert entries["web.config"].is_dir is False and entries["web.config"].size == 1024
    assert entries["Program Files"].is_dir is True  # a dir name with a space survives
    assert entries["huge.iso"].size == 99999999
    assert "blocks" not in " ".join(entries)  # the summary line is not an entry


def test_strip_smbclient_noise_keeps_content() -> None:
    from oscprecon.modules.smb.parsers import strip_smbclient_noise

    peeked = (
        "getting file \\web.config of size 1024 as - (12.5 KiloBytes/sec)\n"
        "<configuration><appSettings>db=prod</appSettings></configuration>\n"
    )
    out = strip_smbclient_noise(peeked)
    assert "getting file" not in out and "<configuration>" in out  # chatter dropped, content kept


def test_is_share_peekable_gates_on_small_text() -> None:
    from oscprecon.modules.smb import is_share_peekable
    from oscprecon.modules.smb.parsers import SmbEntry

    assert is_share_peekable(SmbEntry("web.config", False, 1024)) is True
    assert is_share_peekable(SmbEntry("notes", False, 300)) is True  # no-ext small file
    assert is_share_peekable(SmbEntry("uploads", True, 0)) is False  # directory
    assert is_share_peekable(SmbEntry("backup.zip", False, 500)) is False  # binary ext


def test_smb_share_peek_step_streams_to_stdout() -> None:
    from oscprecon.models import Target
    from oscprecon.modules.smb import SmbModule

    step = SmbModule().share_peek_step(Target(ip="10.0.0.1"), "IT", "web.config", "null")
    line = step.command.shell_line
    assert "smbclient" in line and "//10.0.0.1/IT" in line
    assert 'get "web.config" -' in line  # streams the file to stdout, backslash path form
    assert "-N" in line  # null-session auth (no guest)
