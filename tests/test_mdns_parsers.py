from oscprecon.modules.mdns import parse_mdns_info, parse_mdns_tool

_NMAP = """5353/udp open mdns
| dns-service-discovery:
|   22/tcp ssh
|     Address=10.10.10.33 fe80::1
|   80/tcp http
|_    Address=10.10.10.33
"""


def test_parses_advertised_services() -> None:
    services = {f.value for f in parse_mdns_info(_NMAP) if f.kind == "service"}
    assert "ssh (22/tcp)" in services
    assert "http (80/tcp)" in services


def test_parses_addresses() -> None:
    addrs = {f.value for f in parse_mdns_info(_NMAP) if f.kind == "address"}
    assert "10.10.10.33" in addrs


def test_addresses_deduped() -> None:
    addrs = [f for f in parse_mdns_info(_NMAP) if f.kind == "address"]
    assert len(addrs) == len({a.value for a in addrs})  # no duplicate address findings


def test_missing_sentinel_skipped() -> None:
    assert parse_mdns_info("[missing] nmap — install with: apt install nmap\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_mdns_tool("nope", _NMAP) == []
    assert parse_mdns_tool("mdns-info", _NMAP)
