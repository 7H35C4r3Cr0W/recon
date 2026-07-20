import ipaddress

import pytest

from oscprecon.models import DiscoveredService, Proto
from oscprecon.nmap_scan import (
    ScanSpec,
    build_nmap_command,
    is_entry_target,
    is_range,
    merge_services,
    validate_scan_target,
)


def test_is_entry_target_accepts_ip_hostname_and_slash32() -> None:
    assert is_entry_target("10.10.5.23", "10.10.5.23") is True
    assert is_entry_target("10.10.5.23/32", "10.10.5.23") is True  # entry written as CIDR
    assert is_entry_target("box.htb", "10.10.5.23", "box.htb") is True  # entry hostname
    # NOT the entry: a real range (even one that contains the entry) or a different host
    assert is_entry_target("10.10.5.0/24", "10.10.5.23") is False
    assert is_entry_target("10.10.5.40", "10.10.5.23") is False


def test_merge_services_unions_and_never_drops_prior_ports() -> None:
    existing = [
        DiscoveredService(22, Proto.TCP, "ssh", "OpenSSH", "8.4"),
        DiscoveredService(161, Proto.UDP, "snmp"),
        DiscoveredService(54321, Proto.TCP, "unknown"),  # found only by a prior -p- sweep
    ]
    new = [  # a narrower top-1000 TCP re-scan
        DiscoveredService(
            22, Proto.TCP, "ssh", "OpenSSH", "8.4p1"
        ),  # richer version? blank-fill only
        DiscoveredService(80, Proto.TCP, "http", "nginx", "1.14.2"),
    ]
    merged = merge_services(existing, new)
    ports = {(s.port, s.proto) for s in merged}
    assert (161, Proto.UDP) in ports  # prior UDP port preserved
    assert (54321, Proto.TCP) in ports  # prior high TCP port preserved
    assert (80, Proto.TCP) in ports  # the new port added
    # existing non-blank version is not overwritten (blank-fill semantics)
    ssh = next(s for s in merged if s.port == 22)
    assert ssh.version == "8.4"


def test_merge_fills_blank_fields_from_new_scan() -> None:
    existing = [DiscoveredService(445, Proto.TCP, "microsoft-ds")]  # no product/version
    new = [DiscoveredService(445, Proto.TCP, "microsoft-ds", "Windows Server", "2019")]
    merged = merge_services(existing, new)
    assert len(merged) == 1
    assert merged[0].product == "Windows Server" and merged[0].version == "2019"


def test_build_connect_scan_with_all_options() -> None:
    cmd = build_nmap_command(
        ScanSpec(
            target="10.10.5.0/24",
            scan_type="connect",
            no_ping=True,
            timing="-T4",
            ports="--top-ports 1000",
            version=True,
            default_scripts=True,
            extra="--min-rate 1500",
        )
    )
    assert cmd == "nmap -sT -Pn -T4 --top-ports 1000 -sV -sC --min-rate 1500 10.10.5.0/24"


def test_build_syn_scan_with_nse() -> None:
    cmd = build_nmap_command(
        ScanSpec(target="10.0.0.5", scan_type="syn", ports="-p-", scripts="smb-os-discovery")
    )
    assert cmd == "nmap -sS -T4 -p- -sV --script smb-os-discovery 10.0.0.5"


def test_build_includes_open_and_os_detect() -> None:
    cmd = build_nmap_command(
        ScanSpec(target="10.0.0.5", scripts="http-title", only_open=True, os_detect=True)
    )
    assert cmd == "nmap -sT -T4 --top-ports 1000 -sV --script http-title -O --open 10.0.0.5"


def test_ping_sweep_ignores_open_and_os_detect() -> None:
    # -O / --open are port-scan concepts; a host-discovery sweep must not carry them
    cmd = build_nmap_command(
        ScanSpec(target="10.0.0.0/24", scan_type="ping", only_open=True, os_detect=True)
    )
    assert cmd == "nmap -sn -T4 10.0.0.0/24"


def test_build_no_dns_reason_and_min_rate() -> None:
    cmd = build_nmap_command(ScanSpec(target="10.0.0.5", no_dns=True, reason=True, min_rate=2000))
    assert cmd == "nmap -sT -n -T4 --min-rate 2000 --top-ports 1000 -sV --reason 10.0.0.5"


def test_min_rate_zero_and_flags_off_add_nothing() -> None:
    cmd = build_nmap_command(ScanSpec(target="10.0.0.5", min_rate=0))
    assert cmd == "nmap -sT -T4 --top-ports 1000 -sV 10.0.0.5"  # no --min-rate / -n / --reason


def test_ping_sweep_keeps_no_dns_and_reason_but_not_ports() -> None:
    # -n / --reason are valid in a host-discovery sweep; ports/-sV still dropped
    cmd = build_nmap_command(
        ScanSpec(target="10.0.0.0/24", scan_type="ping", no_dns=True, reason=True, min_rate=1000)
    )
    assert cmd == "nmap -sn -n -T4 --min-rate 1000 --reason 10.0.0.0/24"


def test_ping_sweep_drops_ports_version_and_pn() -> None:
    # -sn is host discovery only; ports/version/scripts/-Pn do not apply and are omitted
    cmd = build_nmap_command(
        ScanSpec(target="10.10.5.0/24", scan_type="ping", no_ping=True, ports="-p-", version=True)
    )
    assert cmd == "nmap -sn -T4 10.10.5.0/24"


def test_udp_scan_type() -> None:
    cmd = build_nmap_command(ScanSpec(target="10.0.0.5", scan_type="udp", version=False, timing=""))
    assert cmd == "nmap -sU --top-ports 1000 10.0.0.5"


def test_target_is_placed_last_and_validated() -> None:
    assert build_nmap_command(ScanSpec("10.0.0.9")).endswith(" 10.0.0.9")
    with pytest.raises(ValueError):
        build_nmap_command(ScanSpec("-oG/tmp/x"))  # a flag-like target is rejected


def test_is_range() -> None:
    assert is_range("10.10.5.0/24") is True
    assert is_range("10.0.0.1") is False
    assert is_range("10.0.0.1/32") is False  # a single host written as CIDR
    assert is_range("nonsense") is False


def test_validate_scan_target_accepts_ip_hostname_cidr() -> None:
    assert validate_scan_target("10.0.0.1") == "10.0.0.1"
    assert validate_scan_target("box.htb") == "box.htb"
    assert validate_scan_target("10.10.5.0/24") == "10.10.5.0/24"


def test_validate_scan_target_rejects_injection_and_bad_cidr() -> None:
    for bad in ("-oG/x", "a b", "$(id)", "h|pipe", "10.10.5.0/33", ""):
        with pytest.raises(ValueError):
            validate_scan_target(bad)


def test_validated_cidr_is_a_real_network() -> None:
    # the returned target must be something nmap accepts — a parseable network
    ipaddress.ip_network(validate_scan_target("172.16.8.0/22"), strict=False)
