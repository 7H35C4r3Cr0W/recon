from pathlib import Path

from oscprecon.modules.vnc import parse_vnc_info, parse_vnc_tool

_FIX = Path(__file__).parent / "fixtures" / "vnc" / "nmap-info.txt"


def _info() -> str:
    return _FIX.read_text(encoding="utf-8")


def test_parses_version_and_security_types() -> None:
    kinds = {(f.kind, f.value) for f in parse_vnc_info(_info())}
    assert ("version", "3.8") in kinds
    assert ("security", "VNC Authentication (2)") in kinds
    assert ("security", "Tight (16)") in kinds


def test_parses_desktop_name() -> None:
    values = {f.kind: f.value for f in parse_vnc_info(_info())}
    assert "root's X desktop" in values["desktop"]


def test_auth_required_has_no_anonymous_access() -> None:
    # VNC Authentication offered (not None) -> not an open display
    assert "access" not in {f.kind for f in parse_vnc_info(_info())}


def test_none_security_type_flags_anonymous_access() -> None:
    text = "| vnc-info:\n|   Protocol version: 3.8\n|   Security types:\n|     None (1)\n"
    values = {f.kind: f.value for f in parse_vnc_info(text)}
    assert values["access"] == "anonymous"  # None auth -> open display


def test_security_types_deduped() -> None:
    text = "Security types:\n  None (1)\n  None (1)\n"
    secs = [f for f in parse_vnc_info(text) if f.kind == "security"]
    assert len(secs) == 1  # duplicate offered type collapses to one finding


def test_missing_sentinel_skipped() -> None:
    assert parse_vnc_info("[missing] nmap — install with: apt install nmap\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_vnc_tool("nope", _info()) == []
