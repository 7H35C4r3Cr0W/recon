from pathlib import Path

from oscprecon.modules.dns.parsers import (
    parse_dig_axfr,
    parse_dig_version,
    parse_dns_tool,
    parse_dnsrecon,
    parse_nmap_dns,
)

FIX = Path(__file__).parent / "fixtures" / "dns"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_parse_dig_version() -> None:
    findings = parse_dig_version(_read("dig-version.txt"))
    assert len(findings) == 1
    assert findings[0].kind == "version"
    assert findings[0].value == "9.11.3-1ubuntu1.13-Ubuntu"  # surrounding quotes stripped


def test_parse_dig_axfr_success() -> None:
    findings = parse_dig_axfr(_read("dig-axfr.txt"))
    records = {f.value for f in findings if f.kind == "record"}
    assert "admin.example.htb. A 10.10.10.10" in records
    assert "internal.example.htb. A 10.10.10.20" in records
    assert "example.htb. MX 10 mail.example.htb." in records
    # the duplicate SOA row (start + end of a zone) is collapsed to one record
    soa = [f for f in findings if f.kind == "record" and "SOA" in f.value]
    assert len(soa) == 1
    transfer = [f for f in findings if f.kind == "zone-transfer"]
    assert transfer and transfer[0].value == "allowed"
    # dig comment / stats lines must not become records
    assert not any("Query time" in f.value or "XFR size" in f.value for f in findings)


def test_parse_dig_axfr_denied() -> None:
    denied = (
        "; <<>> DiG 9.18 <<>> @10.10.10.5 example.htb AXFR\n"
        "; (1 server found)\n"
        ";; global options: +cmd\n"
        "; Transfer failed.\n"
    )
    findings = parse_dig_axfr(denied)
    assert not any(f.kind == "record" for f in findings)
    transfer = [f for f in findings if f.kind == "zone-transfer"]
    assert transfer and transfer[0].value == "denied"


def test_parse_dnsrecon() -> None:
    findings = parse_dnsrecon(_read("dnsrecon-std.txt"))
    records = {f.value for f in findings if f.kind == "record"}
    assert "mail.example.htb MX 10.10.10.6" in records
    assert "admin.example.htb A 10.10.10.10" in records
    assert any(f.kind == "zone-transfer" and f.value == "allowed" for f in findings)
    # the "[+] 0 Records Found" status line must not be parsed as a record
    assert not any("Records" in f.value for f in findings if f.kind == "record")


def test_parse_dnsrecon_info_format() -> None:
    # dnsrecon 1.6.x logs `<timestamp> INFO  TYPE name data` instead of the legacy `[*]` prefix;
    # the parser must read records + zone-transfer from both (regression: silent data loss on Kali).
    findings = parse_dnsrecon(_read("dnsrecon-info.txt"))
    records = {f.value for f in findings if f.kind == "record"}
    assert "admin.example.htb A 10.10.10.10" in records
    assert "mail.example.htb MX 10.10.10.6" in records
    assert "internal.example.htb A 10.10.10.20" in records
    assert any(f.kind == "zone-transfer" and f.value == "allowed" for f in findings)
    # status / progress INFO lines must not become records
    assert not any("Records" in f.value or "Performing" in f.value for f in findings)


def test_parse_nmap_dns() -> None:
    findings = parse_nmap_dns(_read("nmap-dns.txt"))
    versions = [f.value for f in findings if f.kind == "version"]
    assert versions == ["9.11.3-1ubuntu1.13-Ubuntu"]  # nsid preferred over the -sV column
    recursion = [f for f in findings if f.kind == "recursion"]
    assert recursion and recursion[0].value == "enabled"


def test_nmap_dns_recursion_disabled() -> None:
    text = "53/udp open  domain\n|_dns-recursion: Recursion appears to be disabled\n"
    findings = parse_nmap_dns(text)
    assert any(f.kind == "recursion" and f.value == "disabled" for f in findings)


def test_dig_version_skips_shell_sentinels_and_errors() -> None:
    # shell.run writes these into the output file when a tool is missing / blocked; a dig resolver
    # error looks similar — none of them is a version, so parse_dig_version must reject all of them.
    for junk in (
        "[missing] dig — install with: apt install dnsutils\n",
        "[blocked] dig is not on the OSCP-allowed tool list: dig version.bind\n",
        "dig: couldn't get address for 'ns': not known\n",
        ";; connection timed out; no servers could be reached\n",
    ):
        assert parse_dig_version(junk) == []


def test_dispatch_and_garbage() -> None:
    assert parse_dns_tool("unknown", "x") == []
    assert parse_dns_tool("dig-axfr", _read("dig-axfr.txt"))
    assert parse_dig_axfr("total 8\nnot a record line") == []
    assert parse_dig_version(";; connection timed out; no servers could be reached\n") == []
