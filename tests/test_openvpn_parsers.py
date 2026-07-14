from oscprecon.modules.openvpn import parse_openvpn_info, parse_openvpn_tool

_UDP = """Nmap scan report for 10.10.10.39
PORT     STATE SERVICE VERSION
1194/udp open  openvpn OpenVPN
"""

_TCP = "443/tcp open openvpn\n"


def test_confirms_service_and_udp_transport() -> None:
    values = {f.kind: f.value for f in parse_openvpn_info(_UDP)}
    assert values["service"] == "openvpn"
    assert values["transport"] == "udp"


def test_confirms_tcp_transport() -> None:
    values = {f.kind: f.value for f in parse_openvpn_info(_TCP)}
    assert values["transport"] == "tcp"


def test_no_openvpn_line_yields_empty() -> None:
    assert parse_openvpn_info("1194/udp open|filtered unknown\n") == []


def test_missing_sentinel_skipped() -> None:
    assert parse_openvpn_info("[missing] nmap — install with: apt install nmap\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_openvpn_tool("nope", _UDP) == []
    assert parse_openvpn_tool("openvpn-info", _UDP)
