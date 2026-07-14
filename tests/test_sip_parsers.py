from pathlib import Path

from oscprecon.modules.sip import parse_sip_info, parse_sip_tool

_FIX = Path(__file__).parent / "fixtures" / "sip" / "nmap-info.txt"


def _info() -> str:
    return _FIX.read_text(encoding="utf-8")


def test_parses_methods_list() -> None:
    values = {f.kind: f.value for f in parse_sip_info(_info())}
    assert "INVITE" in values["methods"] and "OPTIONS" in values["methods"]


def test_parses_server_banner() -> None:
    values = {f.kind: f.value for f in parse_sip_info(_info())}
    assert "Asterisk" in values["server"]


def test_lone_options_not_treated_as_method_list() -> None:
    # a single verb mention without a comma-list must not become the "methods" finding
    text = "5060/udp open sip\nsome OPTIONS text here\n"
    assert "methods" not in {f.kind for f in parse_sip_info(text)}


def test_missing_sentinel_skipped() -> None:
    assert parse_sip_info("[missing] nmap — install with: apt install nmap\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_sip_tool("nope", _info()) == []
    assert parse_sip_tool("sip-info", _info())
