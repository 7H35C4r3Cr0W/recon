from pathlib import Path

from oscprecon.models import Proto
from oscprecon.modules.nmap import NmapModule, redirect_vhosts

FIXTURES = Path(__file__).parent / "fixtures" / "nmap"


def _raw() -> dict[str, str]:
    return {
        "tcp-versioned.txt": (FIXTURES / "tcp-versioned.txt").read_text(encoding="utf-8"),
        "udp-top100.txt": (FIXTURES / "udp-top100.txt").read_text(encoding="utf-8"),
    }


def test_parenthetical_banner_has_no_product_or_version() -> None:
    # rsync reports just "(protocol version 31)" — no product name, pure extrainfo. It must not be
    # split into product="(protocol version" / version="31)".
    raw = {"x": "873/tcp open  rsync   (protocol version 31)\n"}
    svc = NmapModule().discovered_services(raw)[0]
    assert svc.service == "rsync"
    assert svc.product == "" and svc.version == ""


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


def test_redirect_vhosts_extracts_hostname_from_http_title() -> None:
    # Ignition: nmap's http-title reveals the vhost the IP bounces to.
    raw = {"tcp.txt": "|_http-title: Did not follow redirect to http://ignition.htb/"}
    assert redirect_vhosts(raw) == ["ignition.htb"]
    assert redirect_vhosts({"x": "followed redirect to https://shop.example.com/"}) == [
        "shop.example.com"
    ]


def test_redirect_vhosts_ignores_ip_and_dedupes() -> None:
    assert (
        redirect_vhosts({"x": "Did not follow redirect to http://10.10.10.5/"}) == []
    )  # a bare IP
    raw = {
        "a": "Did not follow redirect to http://ignition.htb/",
        "b": "Did not follow redirect to http://ignition.htb/",  # same host, different file
    }
    assert redirect_vhosts(raw) == ["ignition.htb"]  # deduped
    assert redirect_vhosts({"x": "80/tcp open http nginx"}) == []  # no redirect at all
