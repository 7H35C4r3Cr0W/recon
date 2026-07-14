from pathlib import Path

from oscprecon.modules.ajp import parse_ajp_info, parse_ajp_tool

_FIX = Path(__file__).parent / "fixtures" / "ajp" / "nmap-info.txt"


def _info() -> str:
    return _FIX.read_text(encoding="utf-8")


def test_parses_methods_risky_server() -> None:
    values = {f.kind: f.value for f in parse_ajp_info(_info())}
    assert "GET" in values["methods"] and "POST" in values["methods"]
    assert "PUT" in values["risky"]
    assert values["server"] == "Apache-Coyote/1.1"


def test_sv_only_falls_back_to_version() -> None:
    text = "8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)\n"
    values = {f.kind: f.value for f in parse_ajp_info(text)}
    assert "Apache Jserv" in values["version"]
    assert "methods" not in values


def test_missing_sentinel_skipped() -> None:
    assert parse_ajp_info("[missing] nmap — install with: apt install nmap\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_ajp_tool("nope", _info()) == []
    assert parse_ajp_tool("ajp-info", _info())
