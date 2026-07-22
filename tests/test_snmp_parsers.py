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


def test_cred_hint_no_false_positive() -> None:
    # a value merely ending in 'pass' before '='/':' (compass=, bypass:) must NOT raise a cred note
    benign = 'HOST-RESOURCES-MIB::hrSWRunParameters.9 = STRING: "--bypass=1 Compass: on"\n'
    assert not any(f.kind == "note" and "credential" in f.value for f in parse_snmpwalk(benign))
    # a real password token still raises it
    real = 'HOST-RESOURCES-MIB::hrSWRunParameters.9 = STRING: "db_password=x"\n'
    assert any(f.kind == "note" and "credential" in f.value for f in parse_snmpwalk(real))


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


def test_snmpwalk_flags_leaked_psk_in_syscontact() -> None:
    # HTB Conceal leaks the IKE PSK in sysContact (.1.4.0) as "IKE VPN password PSK - <hash>".
    text = 'iso.3.6.1.2.1.1.4.0 = STRING: "IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43"'
    notes = [f for f in parse_snmpwalk(text) if f.kind == "note"]
    assert any("credential" in f.value for f in notes)  # cred flag fires (a helpful pointer)
    # owner policy: the value IS shown in FULL — the leaked PSK is loot the operator needs.
    assert any("9C8B1A372B1878851BE2C097031B6E43" in f.value for f in notes)


def test_snmpwalk_surfaces_benign_syscontact_without_false_cred() -> None:
    text = 'iso.3.6.1.2.1.1.4.0 = STRING: "admin@corp.local"'
    findings = parse_snmpwalk(text)
    assert any(f.kind == "note" and "sysContact: admin@corp.local" in f.value for f in findings)
    assert not any("credential" in f.value for f in findings)  # a plain email is not a cred


def test_cred_hint_flags_attached_separator_and_no_false_positive() -> None:
    # a psk/secret label with an ATTACHED separator (no space) must still raise the cred FLAG, and
    # (owner policy) the full value is shown — the flag points at the loot, it doesn't hide it.
    for leak in ("PSK: 5f4dcc3b5aa765d61d8327deb882cf99", "secret=Summer2023!", "pwd:hunter2long"):
        text = f'iso.3.6.1.2.1.1.4.0 = STRING: "{leak}"'
        findings = parse_snmpwalk(text)
        assert any("credential" in f.value for f in findings), leak  # cred flag fires
        assert any(leak in f.value for f in findings), leak  # full value shown, not hidden
    # benign English near a keyword must NOT false-fire (that would spam the report with cred flags)
    for benign in ("password protected", "secret sauce", "pass the salt"):
        text = f'iso.3.6.1.2.1.1.4.0 = STRING: "{benign}"'
        findings = parse_snmpwalk(text)
        assert not any("credential" in f.value for f in findings), benign
        assert any(f.value == f"sysContact: {benign}" for f in findings), benign
