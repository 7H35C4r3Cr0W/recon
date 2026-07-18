from pathlib import Path

from oscprecon.modules.vhost.parsers import (
    parse_dnsenum,
    parse_dnsrecon,
    parse_ffuf_vhost,
    parse_gobuster_dns,
    parse_gobuster_vhost,
    parse_vhost_tool,
    parse_wfuzz,
)

FIX = Path(__file__).parent / "fixtures" / "vhost"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_ffuf_vhost() -> None:
    findings = parse_ffuf_vhost(_read("ffuf-vhost.json"), "example.com")
    by_vhost = {f.vhost: f for f in findings}
    assert by_vhost["admin.example.com"].status == 200
    assert by_vhost["admin.example.com"].size == 1234
    assert by_vhost["dev.example.com"].status == 403


def test_gobuster_vhost() -> None:
    findings = parse_gobuster_vhost(_read("gobuster-vhost.txt"))
    by_vhost = {f.vhost: f for f in findings}
    assert by_vhost["admin.example.com"].status == 200
    assert by_vhost["admin.example.com"].size == 1234
    assert by_vhost["dev.example.com"].status == 403


def test_dnsrecon() -> None:
    # dnsrecon 1.6.0 emits "<ts> INFO  A host ip" (no [+] bracket)
    findings = parse_dnsrecon(_read("dnsrecon.txt"))
    by_vhost = {f.vhost: f for f in findings}
    assert by_vhost["admin.example.com"].ip == "10.10.10.5"
    assert by_vhost["dev.example.com"].ip == "10.10.10.6"
    assert "www.example.com" in by_vhost
    # the legacy [+] bracket form still parses
    assert parse_dnsrecon("[+] A legacy.example.com 10.0.0.9")[0].vhost == "legacy.example.com"


def test_gobuster_dns() -> None:
    findings = parse_gobuster_dns(_read("gobuster-dns.txt"))
    by_vhost = {f.vhost: f for f in findings}
    assert by_vhost["www.example.com"].ip == "10.10.10.5"
    assert by_vhost["mail.example.com"].ip == "10.10.10.6"  # first of the comma-separated list
    assert "admin.example.com" in by_vhost  # 'Found:' form, no ip


def test_wfuzz() -> None:
    findings = parse_wfuzz(_read("wfuzz.txt"), "example.com")
    by_vhost = {f.vhost: f for f in findings}
    assert by_vhost["admin.example.com"].status == 200
    assert by_vhost["admin.example.com"].size == 162
    assert by_vhost["dev.example.com"].status == 403


def test_dnsenum() -> None:
    findings = parse_dnsenum(_read("dnsenum.txt"))
    by_vhost = {f.vhost: f for f in findings}
    # host/NS/MX records and the brute-force hits all become vhosts
    assert by_vhost["example.com"].ip == "10.10.10.5"
    assert by_vhost["ns1.example.com"].ip == "10.10.10.5"
    assert by_vhost["mail.example.com"].ip == "10.10.10.6"
    assert by_vhost["admin.example.com"].ip == "10.10.10.10"
    assert by_vhost["dev.example.com"].ip == "10.10.10.20"
    assert by_vhost["internal.example.com"].note == "dnsenum"  # CNAME target row
    # the "AXFR record query failed" line is not a record and must not become a vhost
    assert not any("REFUSED" in v for v in by_vhost)


def test_ffuf_vhost_non_numeric_status_is_defensive() -> None:
    # a non-int status must not raise (would otherwise wedge the GUI worker)
    findings = parse_ffuf_vhost(
        '{"results":[{"input":{"FUZZ":"x"},"status":"OK","length":10}]}', "d"
    )
    assert findings[0].status == 0


def test_dispatch_and_garbage() -> None:
    assert parse_vhost_tool("unknown", "x") == []
    assert parse_ffuf_vhost("not json", "d") == []
    assert parse_vhost_tool("ffuf", _read("ffuf-vhost.json"), "example.com")
    assert parse_vhost_tool("dnsrecon", _read("dnsrecon.txt"))
    assert parse_vhost_tool("dnsenum", _read("dnsenum.txt"))
    assert parse_vhost_tool("gobuster-dns", _read("gobuster-dns.txt"))
    assert parse_vhost_tool("wfuzz", _read("wfuzz.txt"), "example.com")
