from pathlib import Path

from oscprecon.modules.ipmi import parse_ipmi_info, parse_ipmi_tool

_FIX = Path(__file__).parent / "fixtures" / "ipmi" / "nmap-info.txt"


def _info() -> str:
    return _FIX.read_text(encoding="utf-8")


def test_parses_version_and_auth() -> None:
    values = {f.kind: f.value for f in parse_ipmi_info(_info())}
    assert values["version"] == "2.0"
    assert "non_null_user" in values["auth"]


def test_flags_cipher_zero_when_vulnerable() -> None:
    values = {f.kind: f.value for f in parse_ipmi_info(_info())}
    assert values["cipher-zero"] == "enabled"


def test_cipher_zero_not_flagged_without_vuln_state() -> None:
    # a bare mention of the script name (no VULNERABLE state) must not raise a false positive
    text = (
        "623/udp open asf-rmcp\n| ipmi-version:\n|_    IPMI-2.0\nran ipmi-cipher-zero: not vuln\n"
    )
    assert "cipher-zero" not in {f.kind for f in parse_ipmi_info(text)}


def test_missing_sentinel_skipped() -> None:
    assert parse_ipmi_info("[missing] nmap — install with: apt install nmap\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_ipmi_tool("nope", _info()) == []
    assert parse_ipmi_tool("ipmi-info", _info())
