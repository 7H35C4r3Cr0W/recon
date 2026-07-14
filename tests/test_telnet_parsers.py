from pathlib import Path

from oscprecon.modules.telnet import parse_telnet_info, parse_telnet_tool

_FIX = Path(__file__).parent / "fixtures" / "telnet" / "nmap-info.txt"


def _info() -> str:
    return _FIX.read_text(encoding="utf-8")


def test_parses_version_and_encryption() -> None:
    values = {f.kind: f.value for f in parse_telnet_info(_info())}
    assert "Telnet" in values["version"]
    assert values["encryption"] == "not-supported"


def test_parses_ntlm_domain_and_host() -> None:
    values = {f.kind: f.value for f in parse_telnet_info(_info())}
    assert values["hostname"] == "web01.corp.local"
    assert values["domain"] == "corp.local"
    assert values["os-build"] == "10.0.17763"


def test_encryption_supported_flagged() -> None:
    text = "23/tcp open telnet\n| telnet-encryption:\n|_  Telnet server supports encryption\n"
    values = {f.kind: f.value for f in parse_telnet_info(text)}
    assert values["encryption"] == "supported"


def test_missing_sentinel_skipped() -> None:
    assert parse_telnet_info("[missing] nmap — install with: apt install nmap\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_telnet_tool("nope", _info()) == []
    assert parse_telnet_tool("telnet-info", _info())
