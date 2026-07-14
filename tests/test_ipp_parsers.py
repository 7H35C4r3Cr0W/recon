from oscprecon.modules.ipp import IppModule, parse_ipp_curl, parse_ipp_nmap, parse_ipp_tool

_NMAP = """631/tcp open ipp CUPS 2.3.1
| cups-info: CUPS 2.3.1
| cups-queue-info:
|   HP_LaserJet (idle)
|_  Office_Printer (processing)
"""

_CURL = """<HTML><BODY>
<TABLE>
<TR><TD><A HREF="/printers/HP_LaserJet">HP_LaserJet</A></TD></TR>
<TR><TD><A HREF="/printers/Reception">Reception</A></TD></TR>
</BODY></HTML>
"""


def test_nmap_parses_version_and_printers() -> None:
    values = {(f.kind, f.value) for f in parse_ipp_nmap(_NMAP)}
    assert ("version", "CUPS 2.3.1") in values
    assert ("printer", "HP_LaserJet") in values
    assert ("printer", "Office_Printer") in values


def test_curl_parses_printers_from_web_ui() -> None:
    names = {f.value for f in parse_ipp_curl(_CURL) if f.kind == "printer"}
    assert names == {"HP_LaserJet", "Reception"}


def test_module_dedupes_printers_across_steps() -> None:
    module = IppModule()
    found = module.parse({"ipp-nmap": _NMAP, "ipp-curl": _CURL})
    printers = [f.fields["value"] for f in found if f.fields["kind"] == "printer"]
    assert printers.count("HP_LaserJet") == 1  # same printer from both steps collapses


def test_missing_sentinel_skipped() -> None:
    assert parse_ipp_nmap("[missing] nmap — install with: apt install nmap\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_ipp_tool("nope", _NMAP) == []
    assert parse_ipp_tool("ipp-nmap", _NMAP)
