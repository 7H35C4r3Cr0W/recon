from pathlib import Path

from oscprecon.modules.oracle import parse_oracle_info, parse_oracle_tool

_FIX = Path(__file__).parent / "fixtures" / "oracle" / "nmap-info.txt"


def _info() -> str:
    return _FIX.read_text(encoding="utf-8")


def test_parses_tns_version() -> None:
    values = {f.kind: f.value for f in parse_oracle_info(_info())}
    assert values["version"] == "11.2.0.2.0"


def test_sv_only_version_fallback() -> None:
    text = "1521/tcp open oracle-tns Oracle TNS Listener 19.0.0.0.0\n"
    values = {f.kind: f.value for f in parse_oracle_info(text)}
    assert values["version"] == "19.0.0.0.0"


def test_missing_sentinel_skipped() -> None:
    assert parse_oracle_info("[missing] nmap — install with: apt install nmap\n") == []


def test_no_version_yields_empty() -> None:
    assert parse_oracle_info("1521/tcp filtered oracle-tns\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_oracle_tool("nope", _info()) == []
    assert parse_oracle_tool("oracle-info", _info())
