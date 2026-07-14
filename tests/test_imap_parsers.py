from pathlib import Path

from oscprecon.modules.imap import parse_imap_info, parse_imap_tool

_FIX = Path(__file__).parent / "fixtures" / "imap" / "nmap-info.txt"


def _info() -> str:
    return _FIX.read_text(encoding="utf-8")


def test_parses_version_and_capabilities() -> None:
    values = {f.kind: f.value for f in parse_imap_info(_info())}
    assert "Exchange" in values["version"]
    assert "IMAP4rev1" in values["capabilities"]


def test_parses_starttls_and_auth_mechs() -> None:
    values = {f.kind: f.value for f in parse_imap_info(_info())}
    assert values["starttls"] == "yes"
    assert "NTLM" in values["auth"]


def test_parses_ntlm_domain_and_host() -> None:
    values = {f.kind: f.value for f in parse_imap_info(_info())}
    assert values["hostname"] == "mail01.corp.local"
    assert values["domain"] == "corp.local"
    assert values["os-build"] == "10.0.17763"


def test_starttls_no_when_absent() -> None:
    text = "143/tcp open imap Dovecot\n| imap-capabilities: IMAP4rev1 AUTH=PLAIN\n"
    values = {f.kind: f.value for f in parse_imap_info(text)}
    assert values["starttls"] == "no"


def test_missing_sentinel_skipped() -> None:
    assert parse_imap_info("[missing] nmap — install with: apt install nmap\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_imap_tool("nope", _info()) == []
    assert parse_imap_tool("imap-info", _info())
