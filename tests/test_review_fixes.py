"""Regression tests for the sweeping-review bug fixes (security + parse correctness).

Each test names the finding number it locks in so a future refactor can't silently reintroduce it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oscprecon.edb import add_edb
from oscprecon.finding_severity import classify
from oscprecon.findings import add_findings, load_findings
from oscprecon.modules.ftp import is_peekable as _peek
from oscprecon.modules.nmap import parse_port_line
from oscprecon.modules.smb.parsers import parse_netexec_shares, readable_shares
from oscprecon.modules.vhost.parsers import parse_gobuster_dns
from oscprecon.nmap_scan import ScanSpec, build_nmap_command, is_entry_target
from oscprecon.references import ExploitHit, _title_matches_version
from oscprecon.references.live_hacktricks import html_to_markdown
from oscprecon.reporter import _redacted_history
from oscprecon.shell import _redact_cmdline, policy_violation
from oscprecon.workspace import portability


# --- #2 secret redaction before logging -------------------------------------------------------
def test_redact_masks_mysql_inline_password() -> None:
    line = _redact_cmdline(["mysql", "-h", "10.10.10.5", "-u", "root", "-pRootPass1"])
    assert "RootPass1" not in line
    assert "<redacted len=9>" in line


def test_redact_masks_long_password_flag_for_any_tool() -> None:
    line = _redact_cmdline(["wpscan", "--url", "http://x", "--password", "hunter2"])
    assert "hunter2" not in line and "<redacted len=7>" in line


def test_redact_leaves_nmap_port_flag_alone() -> None:
    # -p on nmap is ports, not a password — it must NOT be masked (nmap is not a cred tool)
    line = _redact_cmdline(["nmap", "-p", "80,443", "10.10.10.5"])
    assert "80,443" in line


def test_redact_masks_credential_token_shapes() -> None:
    # the URI / impacket-positional / -U user%pass forms the tool SHIPS as Tier-2 recon commands —
    # these carry the secret INSIDE one argv token, invisible to the flag-based masking
    uri = _redact_cmdline(["psql", "postgresql://svc:S3cretPass@10.0.0.5:5432/db"])
    assert "S3cretPass" not in uri and "svc:" in uri and "@10.0.0.5:5432/db" in uri
    # impacket positional — GetADUsers.py is not even a cred-tool, but domain/user:pass must mask
    imp = _redact_cmdline(["GetADUsers.py", "corp.local/bob:S3cretPass", "-dc-ip", "10.0.0.5"])
    assert "S3cretPass" not in imp and "corp.local/bob:" in imp
    imp2 = _redact_cmdline(["impacket-secretsdump", "corp.local/bob:S3cretPass@10.0.0.5"])
    assert "S3cretPass" not in imp2 and "@10.0.0.5" in imp2
    # -U user%pass (split flag+value, and concatenated) — smbclient/rpcclient
    u1 = _redact_cmdline(["smbclient", "//10.0.0.5/share", "-U", "svc%S3cretPass"])
    assert "S3cretPass" not in u1 and "svc%" in u1
    u2 = _redact_cmdline(["rpcclient", "-Uadmin%Passw0rd", "10.0.0.5"])
    assert "Passw0rd" not in u2


def test_redact_masks_all_trailing_nargs_after_secret_flag() -> None:
    # -p with several inline values (blocked spray) must mask EVERY password, not just the first,
    # since the blocked-command message is written to the profile's output file on disk
    line = _redact_cmdline(["netexec", "smb", "10.0.0.1", "-u", "admin", "-p", "pw1", "pw2", "pw3"])
    assert "pw1" not in line and "pw2" not in line and "pw3" not in line


def test_redact_does_not_touch_benign_tokens() -> None:
    # a -U with no password, a UNC path, and a plain URL must be left intact
    assert _redact_cmdline(["smbclient", "-L", "//10.0.0.5/", "-U", "guest"]).endswith("guest")
    assert "//10.0.0.5/" in _redact_cmdline(["smbclient", "-L", "//10.0.0.5/", "-N"])
    assert "http://10.0.0.5/" in _redact_cmdline(["feroxbuster", "-u", "http://10.0.0.5/"])


# --- #3 product starting with a digit -----------------------------------------------------------
def test_parse_port_line_digit_product_keeps_version() -> None:
    svc = parse_port_line("8080/tcp open http 3proxy 0.8.13")
    assert svc is not None
    assert svc.product == "3proxy"
    assert svc.version == "0.8.13"


def test_parse_port_line_edition_year_is_not_the_version() -> None:
    # regression: an edition YEAR (bare integer) inside a product name was taken as the version,
    # dropping the real dotted version — corrupting the graph/report/searchsploit query
    svc = parse_port_line("1433/tcp open ms-sql-s Microsoft SQL Server 2017 14.00.1000.00; RTM")
    assert svc is not None
    assert svc.product.startswith("Microsoft SQL Server 2017")
    assert svc.version.startswith("14.00.1000.00")
    # a normal dotted version still wins from position 1
    ng = parse_port_line("80/tcp open http nginx 1.18.0")
    assert ng is not None and ng.product == "nginx" and ng.version == "1.18.0"


# --- #20 entry-target hostname case-insensitivity ----------------------------------------------
def test_is_entry_target_hostname_casefold() -> None:
    assert is_entry_target("ACTIVE.HTB", "10.10.10.5", "active.htb") is True


# --- #22 build_nmap_command rejects file-writing flags -----------------------------------------
def test_build_nmap_command_rejects_output_flag_in_ports() -> None:
    with pytest.raises(ValueError):
        build_nmap_command(ScanSpec(target="10.10.5.5", ports="-p 80 -oN /home/hacker/.zshrc"))


def test_build_nmap_command_rejects_metachar_in_extra() -> None:
    with pytest.raises(ValueError):
        build_nmap_command(ScanSpec(target="10.10.5.5", extra="; rm -rf ~"))


def test_build_nmap_command_allows_normal_fields() -> None:
    cmd = build_nmap_command(ScanSpec(target="10.10.5.5", ports="-p 80", scripts="http-title"))
    assert cmd.startswith("nmap ") and "-oN" not in cmd


# --- #25 gobuster dns must be a real hostname --------------------------------------------------
def test_gobuster_dns_rejects_version_token() -> None:
    assert parse_gobuster_dns("2.4.5\n") == []


def test_gobuster_dns_accepts_hostname() -> None:
    got = parse_gobuster_dns("Found: admin.example.com\n")
    assert len(got) == 1 and got[0].vhost == "admin.example.com"


# --- #28 findings dedup preserves distinct detail ----------------------------------------------
def test_findings_dedup_keeps_distinct_detail(tmp_path: Path) -> None:
    add_findings(
        tmp_path,
        [
            {"module": "smb", "kind": "policy", "value": "lockout", "detail": "threshold: 5"},
            {"module": "smb", "kind": "policy", "value": "lockout", "detail": "duration: 30m"},
        ],
    )
    stored = load_findings(tmp_path)
    details = {f.get("detail") for f in stored}
    assert details == {"threshold: 5", "duration: 30m"}


# --- #30 severity: a negated signal is not escalated -------------------------------------------
def test_classify_negated_anonymous_is_info() -> None:
    assert classify("note", "anonymous access is disabled") == "info"


def test_classify_real_anonymous_still_flags() -> None:
    assert classify("access", "anonymous login allowed") != "info"


# --- #31 edb write never raises on a read-only dir ---------------------------------------------
def test_add_edb_survives_unwritable_dir(tmp_path: Path) -> None:
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    hit = ExploitHit(edb_id="1", title="x", url="http://x", path="/tmp/x")
    try:
        # must return the in-memory list, not raise, when the dir can't be written
        result = add_edb(ro, service="http", product="p", version="1", hits=[hit])
        assert isinstance(result, list)
    finally:
        ro.chmod(0o700)


# --- #44 secret material is never peeked -------------------------------------------------------
def test_peek_skips_private_key_and_htpasswd() -> None:
    from oscprecon.modules.ftp.parsers import FtpEntry

    assert _peek(FtpEntry("id_rsa", False, 1600)) is False
    assert _peek(FtpEntry("server.key", False, 200)) is False
    assert _peek(FtpEntry(".htpasswd", False, 120)) is False
    assert _peek(FtpEntry("notes.txt", False, 200)) is True


# --- #45 netexec share perms read only the Permissions column ----------------------------------
def test_netexec_shares_empty_perms_with_read_remark_not_readable() -> None:
    text = (
        "SMB  10.10.10.5  445  DC  Share           Permissions     Remark\n"
        "SMB  10.10.10.5  445  DC  -----           -----------     ------\n"
        "SMB  10.10.10.5  445  DC  backup                          READ\n"
        "SMB  10.10.10.5  445  DC  data            READ            files\n"
    )
    findings = parse_netexec_shares(text)
    by_name = {f.value: f.detail for f in findings}
    assert by_name.get("backup") == ""  # 'READ' was the Remark, not a permission
    assert "READ" in by_name.get("data", "")
    readable = set(readable_shares(findings))
    assert "backup" not in readable and "data" in readable


# --- #4 auto vhost ffuf sweep carries -ac (wildcard filtering) ---------------------------------
def test_auto_vhost_ffuf_has_autocalibration() -> None:
    from oscprecon.models import Target
    from oscprecon.modules.vhost import VhostModule

    cmds = VhostModule().commands(Target(ip="10.10.10.5", hostname="thetoppers.htb"), [])
    ffuf = next(c.shell_line for c in cmds if c.shell_line.startswith("ffuf"))
    assert "-ac" in ffuf.split() and "-fs" not in ffuf.split()


# --- #12/#37 atomic credential edit ------------------------------------------------------------
def _profile_at(tmp_path: Path):  # type: ignore[no-untyped-def]
    from oscprecon.models import Target
    from oscprecon.profile import Profile

    return Profile(profile_name="t", directory=tmp_path, target=Target(ip="10.10.10.5"))


def test_replace_credential_is_in_place(tmp_path: Path) -> None:
    from oscprecon.models import Credential

    prof = _profile_at(tmp_path)
    a = Credential(username="alice", domain="corp", secret="P@ss", source="smb")
    b = Credential(username="bob", domain="corp", secret="P@ss", source="smb")
    prof.add_credential(a)
    prof.add_credential(b)
    edited = Credential(
        username="bob", domain="corp", secret="NewP@ss", source="smb", notes="rotated"
    )
    prof.replace_credential(b, edited)
    creds = prof.credentials()
    assert len(creds) == 2  # alice + edited bob, no loss, no accidental delete
    bob = next(c for c in creds if c.username == "bob")
    assert bob.secret == "NewP@ss" and bob.notes == "rotated"


def test_replace_credential_collision_keeps_one_row(tmp_path: Path) -> None:
    from oscprecon.models import Credential

    prof = _profile_at(tmp_path)
    a = Credential(username="alice", domain="corp", secret="P@ss", source="smb")
    b = Credential(username="bob", domain="corp", secret="P@ss", source="smb")
    prof.add_credential(a)
    prof.add_credential(b)
    # rename bob -> alice (colliding key). The edit must win and not silently vanish (#37).
    collide = Credential(
        username="alice", domain="corp", secret="P@ss", source="smb", notes="merged"
    )
    prof.replace_credential(b, collide)
    creds = prof.credentials()
    assert len(creds) == 1
    assert creds[0].username == "alice" and creds[0].notes == "merged"


# --- #36 http panel re-derives the port from a new URL -----------------------------------------
def test_port_from_url() -> None:
    from oscprecon.gui.widgets.http_panel import _port_from_url

    assert _port_from_url("http://vhost/") == 80
    assert _port_from_url("https://vhost/") == 443
    assert _port_from_url("http://vhost:8080/app") == 8080


# --- #40 delete_project refuses a symlink entry ------------------------------------------------
def test_delete_project_refuses_symlink(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    real = ws / "real"
    real.mkdir()
    (real / "profile.json").write_text("{}")
    link = ws / "link"
    link.symlink_to(real)
    with pytest.raises(portability.ProjectArchiveError):
        portability.delete_project(link, ws)
    assert real.exists()  # the real project must survive


# --- 2026-07-20 engine-core review: policy holes + secret redaction ---------------------------
def test_wpscan_brute_blocks_equals_and_concatenated_forms() -> None:
    # the =-form and concatenated short form must be blocked in default mode, like the space form
    for argv in (
        ["wpscan", "--url", "http://x", "--passwords=rockyou.txt"],
        ["wpscan", "--url", "http://x", "-Prockyou.txt"],
        ["wpscan", "--url", "http://x", "--usernames=u.txt"],
        ["wpscan", "--url", "http://x", "-Uu.txt"],
    ):
        assert policy_violation(argv) is not None, argv
        assert policy_violation(argv, spray=True) is None  # Spray mode unlocks it
    assert policy_violation(["wpscan", "--url", "http://x", "--enumerate", "u"]) is None  # recon ok


def test_nmap_script_all_and_star_are_blocked() -> None:
    assert policy_violation(["nmap", "--script", "all", "10.0.0.1"]) is not None
    assert policy_violation(["nmap", "--script", "*", "10.0.0.1"]) is not None
    assert policy_violation(["nmap", "--script=all", "10.0.0.1"]) is not None
    assert policy_violation(["nmap", "--script", "all", "10.0.0.1"], spray=True) is None
    # legitimate recon scripts and the allowed recon-brute stay allowed
    assert policy_violation(["nmap", "--script", "http-title,ssl-cert", "10.0.0.1"]) is None
    assert policy_violation(["nmap", "--script", "oracle-sid-brute", "10.0.0.1"]) is None


def test_netexec_relative_wordlist_is_blocked_without_touching_disk() -> None:
    # a relative wordlist path that doesn't resolve from cwd must still be caught by its extension
    assert policy_violation(["netexec", "smb", "10.0.0.1", "-u", "users.txt", "-p", "pass.txt"])
    assert policy_violation(["netexec", "smb", "10.0.0.1", "-p", "wordlist.lst"])
    # a single interactive credential (no wordlist extension) stays allowed
    assert (
        policy_violation(["netexec", "smb", "10.0.0.1", "-u", "administrator", "-p", "sa"]) is None
    )
    assert policy_violation(["netexec", "smb", "10.0.0.1", "-u", "guest", "-p", ""]) is None


def test_redact_masks_impacket_single_dash_hashes_for_any_tool() -> None:
    # -hashes (impacket single-dash) must be masked even on a bare, un-prefixed script name (§6)
    line = _redact_cmdline(
        ["impacket-mssqlclient", "-hashes", "aad3b435:c0ffeec0ffee", "d/u@1.2.3.4"]
    )
    assert "aad3b435:c0ffeec0ffee" not in line and "<redacted" in line
    bare = _redact_cmdline(["GetNPUsers.py", "-hashes", "aad:bbbb", "d/u"])
    assert "aad:bbbb" not in bare and "<redacted" in bare


# --- 2026-07-20 references + reporter review --------------------------------------------------
def test_version_match_uses_token_boundary_for_full_version() -> None:
    # a bare major.minor version must NOT substring-match a longer number (mis-flagged exploits)
    assert _title_matches_version("SomeApp 2.41 XSS", "2.4", "2.4") is False
    assert _title_matches_version("foo 12.4 bar", "2.4", "2.4") is False
    assert _title_matches_version("x 1.20 y", "1.2", "1.2") is False
    assert (
        _title_matches_version("nginx 2.4.49 RCE", "2.4", "2.4") is True
    )  # genuine prefix matches


def test_html_sanitizer_void_end_tag_does_not_leak_chrome() -> None:
    md = html_to_markdown(
        "<main><nav>NAVCHROME<meta charset=utf8></meta>LEAKED<p>x</p></nav><p>body</p></main>"
    )
    text = md[0] if isinstance(md, tuple) else md
    assert "NAVCHROME" not in text and "LEAKED" not in text  # a </meta> must not end the skip early
    assert "body" in text  # the real content after the nav still renders


def test_report_command_log_redacts_credentialed_shell_line() -> None:
    out = _redacted_history(
        [{"module": "smb", "shell_line": "impacket-secretsdump corp/bob:S3cretPass@10.0.0.5"}]
    )
    assert "S3cretPass" not in out[0]["shell_line"] and "<redacted" in out[0]["shell_line"]
