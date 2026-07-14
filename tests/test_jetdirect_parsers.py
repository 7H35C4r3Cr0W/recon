from oscprecon.modules.jetdirect import parse_jetdirect_info, parse_jetdirect_tool

_NMAP = """9100/tcp open  jetdirect  HP LaserJet 4250 firmware 20140217
"""

_PDL = "9100/tcp open  pdl-datastream  Lexmark printer\n"


def test_parses_printer_product() -> None:
    values = {f.kind: f.value for f in parse_jetdirect_info(_NMAP)}
    assert "HP LaserJet 4250" in values["product"]


def test_parses_firmware_version() -> None:
    values = {f.kind: f.value for f in parse_jetdirect_info(_NMAP)}
    assert values["version"] == "20140217"


def test_pdl_datastream_service_name_parses() -> None:
    values = {f.kind: f.value for f in parse_jetdirect_info(_PDL)}
    assert "Lexmark" in values["product"]


def test_no_banner_yields_empty() -> None:
    assert (
        parse_jetdirect_info("9100/tcp open jetdirect\n") == []
    )  # no product string after service


def test_missing_sentinel_skipped() -> None:
    assert parse_jetdirect_info("[missing] nmap — install with: apt install nmap\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_jetdirect_tool("nope", _NMAP) == []
    assert parse_jetdirect_tool("jetdirect-info", _NMAP)
