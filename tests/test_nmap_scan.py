import ipaddress

import pytest

from oscprecon.nmap_scan import (
    ScanSpec,
    build_nmap_command,
    is_range,
    validate_scan_target,
)


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
