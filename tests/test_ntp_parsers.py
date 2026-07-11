from pathlib import Path

from oscprecon.modules.ntp.parsers import parse_ntp_tool, parse_ntpdate, parse_ntpq

FIX = Path(__file__).parent / "fixtures" / "ntp"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_ntpq_readlist_info_and_stratum() -> None:
    findings = parse_ntpq(_read("ntpq-readlist.txt"))
    info = {f.value for f in findings if f.kind == "info"}
    assert any(v.startswith("ntpd version: ntpd 4.2.8p15") for v in info)
    assert "OS: Linux/5.4.0-91-generic" in info
    assert "processor: x86_64" in info
    assert any(f.kind == "stratum" and f.value == "3" for f in findings)


def test_ntpq_sysinfo_colon_stratum() -> None:
    # sysinfo renders `stratum:  3` (colon + spaces) rather than `stratum=3`
    findings = parse_ntpq("system peer:  192.168.1.1\nstratum:            3\nleap indicator: 00\n")
    assert any(f.kind == "stratum" and f.value == "3" for f in findings)


def test_ntpdate_stratum_and_server() -> None:
    findings = parse_ntpdate(_read("ntpdate.txt"))
    stratum = next(f for f in findings if f.kind == "stratum")
    assert stratum.value == "3"
    assert "10.10.10.180" in stratum.detail


def test_dispatch_and_garbage() -> None:
    assert parse_ntp_tool("unknown", "x") == []
    assert parse_ntp_tool("ntpq-readlist", _read("ntpq-readlist.txt"))
    assert parse_ntp_tool("ntpq-sysinfo", _read("ntpq-readlist.txt"))
    assert parse_ntp_tool("ntpdate", _read("ntpdate.txt"))
    assert parse_ntpq("no ntp variables here\n") == []
    assert parse_ntpdate("no server line\n") == []
