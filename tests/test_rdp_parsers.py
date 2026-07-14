from pathlib import Path

from oscprecon.modules.rdp import parse_rdp_info, parse_rdp_tool

_FIX = Path(__file__).parent / "fixtures" / "rdp" / "nmap-info.txt"


def _info() -> str:
    return _FIX.read_text(encoding="utf-8")


def test_parses_hostname_domain_osbuild() -> None:
    values = {f.kind: f.value for f in parse_rdp_info(_info())}
    assert values["hostname"] == "RDP-01.corp.local"
    assert values["domain"] == "corp.local"
    assert values["os-build"] == "10.0.17763"


def test_parses_protocol_version_and_encryption() -> None:
    kinds = {(f.kind, f.value) for f in parse_rdp_info(_info())}
    assert ("version", "RDP protocol 5.1") in kinds
    assert ("encryption", "Client Compatible") in kinds


def test_nla_optional_when_both_layers_accept() -> None:
    values = {f.kind: f.value for f in parse_rdp_info(_info())}
    assert values["nla"] == "optional"


def test_nla_not_enforced_when_native_only() -> None:
    text = (
        "| rdp-enum-encryption:\n|   Security layer\n"
        "|     Native RDP: SUCCESS\n|     CredSSP (NLA): FAILED\n"
        "|_  RDP Protocol Version:  5.0\n"
    )
    values = {f.kind: f.value for f in parse_rdp_info(text)}
    assert values["nla"] == "not-enforced"


def test_standalone_domain_equal_host_is_skipped() -> None:
    text = "| rdp-ntlm-info:\n|   NetBIOS_Computer_Name: WIN-01\n|   NetBIOS_Domain_Name: WIN-01\n"
    kinds = {f.kind for f in parse_rdp_info(text)}
    assert "hostname" in kinds
    assert "domain" not in kinds  # domain == host -> standalone box, not an AD domain


def test_workgroup_domain_is_skipped() -> None:
    text = "| rdp-ntlm-info:\n|   NetBIOS_Computer_Name: PC-1\n|   NetBIOS_Domain_Name: WORKGROUP\n"
    assert "domain" not in {f.kind for f in parse_rdp_info(text)}


def test_missing_sentinel_skipped() -> None:
    assert parse_rdp_info("[missing] nmap — install with: apt install nmap\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_rdp_tool("nope", _info()) == []
    assert parse_rdp_tool("rdp-info", _info())  # known key parses
