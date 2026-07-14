from pathlib import Path

from oscprecon.models import Proto
from oscprecon.modules.nmap import NmapModule

FIXTURES = Path(__file__).parent / "fixtures" / "nmap"


def _raw() -> dict[str, str]:
    return {
        "tcp-versioned.txt": (FIXTURES / "tcp-versioned.txt").read_text(encoding="utf-8"),
        "udp-top100.txt": (FIXTURES / "udp-top100.txt").read_text(encoding="utf-8"),
    }


def test_parses_open_tcp_ports() -> None:
    services = {(s.port, s.proto): s for s in NmapModule().discovered_services(_raw())}

    assert (22, Proto.TCP) in services
    assert services[(22, Proto.TCP)].service == "ssh"
    assert "OpenSSH" in services[(22, Proto.TCP)].product

    assert services[(80, Proto.TCP)].service == "http"
    assert services[(80, Proto.TCP)].product == "nginx"
    assert services[(80, Proto.TCP)].version == "1.18.0"

    # multi-word product must stay intact, version must be just the number (extrainfo dropped)
    assert services[(22, Proto.TCP)].version == "8.4p1"
    assert services[(139, Proto.TCP)].product == "Samba smbd"
    assert services[(139, Proto.TCP)].version == "4.6.2"

    assert services[(445, Proto.TCP)].service == "microsoft-ds"


def test_parses_udp_ports() -> None:
    services = {(s.port, s.proto): s for s in NmapModule().discovered_services(_raw())}

    assert (161, Proto.UDP) in services
    assert services[(161, Proto.UDP)].service == "snmp"
    assert (123, Proto.UDP) in services


def test_ignores_non_port_lines() -> None:
    services = NmapModule().discovered_services({"noise": "Host is up (0.02s latency).\nblah\n"})
    assert services == []


def test_findings_derived_from_services() -> None:
    findings = NmapModule().parse(_raw())
    titles = {f.title for f in findings}
    assert any("22/tcp" in t for t in titles)
    assert all(f.port is not None for f in findings)
