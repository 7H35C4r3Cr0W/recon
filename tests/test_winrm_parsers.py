from oscprecon.modules.winrm import parse_winrm_http, parse_winrm_nxc, parse_winrm_tool

_NXC = (
    "WINRM  10.10.10.5  5985  DC01  [*] Windows Server 2019 Build 17763 "
    "(name:DC01) (domain:corp.local)\n"
)
_HTTP = "HTTP/1.1 405 Method Not Allowed\r\nServer: Microsoft-HTTPAPI/2.0\r\nContent-Length: 0\r\n"


def test_nxc_parses_host_os_domain() -> None:
    values = {f.kind: f.value for f in parse_winrm_nxc(_NXC)}
    assert values["host"] == "DC01"
    assert "Windows Server 2019" in values["os"]
    assert values["domain"] == "corp.local"


def test_nxc_strips_ansi_colour_codes() -> None:
    coloured = "\x1b[1;34mWINRM\x1b[0m 10.0.0.1 5985 PC [*] Windows 10 (name:PC) (domain:PC)\n"
    values = {f.kind: f.value for f in parse_winrm_nxc(coloured)}
    assert values["host"] == "PC"
    assert "domain" not in values  # domain == host -> standalone, skipped


def test_http_405_flags_live_endpoint_and_server() -> None:
    values = {f.kind: f.value for f in parse_winrm_http(_HTTP)}
    assert "live" in values["endpoint"]
    assert values["server"] == "Microsoft-HTTPAPI/2.0"


def test_http_200_is_not_a_winrm_endpoint() -> None:
    assert not any(
        f.kind == "endpoint" for f in parse_winrm_http("HTTP/1.1 200 OK\r\nServer: nginx\r\n")
    )


def test_missing_sentinel_skipped() -> None:
    assert parse_winrm_nxc("[missing] netexec — install with: apt install netexec\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_winrm_tool("nope", _NXC) == []
    assert parse_winrm_tool("winrm-nxc", _NXC)
