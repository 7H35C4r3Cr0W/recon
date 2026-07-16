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
from oscprecon.references import ExploitHit
from oscprecon.shell import _redact_cmdline
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


# --- #3 product starting with a digit -----------------------------------------------------------
def test_parse_port_line_digit_product_keeps_version() -> None:
    svc = parse_port_line("8080/tcp open http 3proxy 0.8.13")
    assert svc is not None
    assert svc.product == "3proxy"
    assert svc.version == "0.8.13"


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
