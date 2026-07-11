from pathlib import Path

from oscprecon.modules.snmp.parsers import (
    parse_nmap_snmp,
    parse_onesixtyone,
    parse_snmp_tool,
    parse_snmpwalk,
)

FIX = Path(__file__).parent / "fixtures" / "snmp"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_onesixtyone_communities() -> None:
    findings = parse_onesixtyone(_read("onesixtyone.txt"))
    communities = {f.value for f in findings if f.kind == "community"}
    assert communities == {"public", "private"}
    banners = {f.value for f in findings if f.kind == "banner"}
    assert any("Windows" in b for b in banners)


def test_onesixtyone_ignores_header() -> None:
    # the "Scanning N hosts, M communities" header line must not become a finding
    assert parse_onesixtyone("Scanning 1 hosts, 51 communities\n") == []


def test_nmap_snmp_banner_and_processes() -> None:
    findings = parse_nmap_snmp(_read("nmap-snmp.txt"))
    banners = [f.value for f in findings if f.kind == "banner"]
    assert any("SNMPv1 server" in b for b in banners)  # from the version line
    assert any(b.startswith("Linux nix01") for b in banners)  # from snmp-sysdescr
    procs = {f.value for f in findings if f.kind == "process"}
    assert {"systemd", "sshd"} <= procs


def test_nmap_snmp_interfaces_are_ip_only() -> None:
    ifaces = {f.value for f in parse_nmap_snmp(_read("nmap-snmp.txt")) if f.kind == "interface"}
    # the IP is isolated from the trailing "Netmask: ..." on the same line
    assert ifaces == {"127.0.0.1", "10.10.10.180"}


def test_snmpwalk_banner_processes_and_cred_hint() -> None:
    findings = parse_snmpwalk(_read("snmpwalk.txt"))
    assert any(f.kind == "banner" and f.value.startswith("Linux nix01") for f in findings)
    procs = {f.value for f in findings if f.kind == "process"}
    assert {"systemd", "sshd", "backup.sh"} <= procs
    # the --password= in hrSWRunParameters is flagged, but the secret is NOT copied into a finding
    notes = [f for f in findings if f.kind == "note" and "credential" in f.value]
    assert notes
    assert not any("Sup3rS3cret" in (f.value + f.detail) for f in findings)


def test_snmpwalk_windows_users() -> None:
    text = (
        'iso.3.6.1.4.1.77.1.2.25.1.1.5 = STRING: "Administrator"\n'
        'iso.3.6.1.4.1.77.1.2.25.1.1.6 = STRING: "svc_backup"\n'
    )
    users = {f.value for f in parse_snmpwalk(text) if f.kind == "user"}
    assert users == {"Administrator", "svc_backup"}


def test_dispatch_and_garbage() -> None:
    assert parse_snmp_tool("unknown", "x") == []
    assert parse_snmp_tool("onesixtyone", _read("onesixtyone.txt"))
    assert parse_snmp_tool("nmap-snmp", _read("nmap-snmp.txt"))
    assert parse_snmp_tool("snmpwalk", _read("snmpwalk.txt"))
    assert parse_onesixtyone("no communities here\n") == []
    assert parse_snmpwalk("not an oid line\n") == []
