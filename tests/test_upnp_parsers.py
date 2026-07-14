from oscprecon.modules.upnp import parse_upnp_info, parse_upnp_tool

_NMAP = """1900/udp open upnp
| upnp-info:
|   Server: Linux/2.6 UPnP/1.0 MiniUPnPd/1.9
|   Location: http://10.10.10.35:5000/rootDesc.xml
|     Name: Living Room Gateway
|     Manufacturer: Acme Networks
|_    Model: AC-1900
"""


def test_parses_server_and_location() -> None:
    values = {f.kind: f.value for f in parse_upnp_info(_NMAP)}
    assert "MiniUPnPd/1.9" in values["server"]
    assert values["location"] == "http://10.10.10.35:5000/rootDesc.xml"


def test_parses_device_details() -> None:
    values = {f.kind: f.value for f in parse_upnp_info(_NMAP)}
    assert values["device"] == "Living Room Gateway"
    assert values["manufacturer"] == "Acme Networks"
    assert values["model"] == "AC-1900"


def test_missing_sentinel_skipped() -> None:
    assert parse_upnp_info("[missing] nmap — install with: apt install nmap\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_upnp_tool("nope", _NMAP) == []
    assert parse_upnp_tool("upnp-info", _NMAP)
