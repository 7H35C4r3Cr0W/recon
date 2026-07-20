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


def test_filtered_port_surfaced_as_finding_not_service() -> None:
    # Drive: 3000/tcp is filtered from outside but runs Gitea (reachable after a foothold + SSH
    # forward). It must NOT become a discovered service (would be a phantom actionable node), but
    # SHOULD surface as an informational finding so the port isn't silently lost. Deduped by port.
    mod = NmapModule()
    raw = {
        "top": "22/tcp open ssh\n80/tcp open http\n3000/tcp filtered ppp\n",
        "full": "22/tcp open ssh\n3000/tcp filtered ppp\n",
    }
    assert 3000 not in {s.port for s in mod.discovered_services(raw)}
    filtered = [f for f in mod.parse(raw) if f.service == "filtered"]
    assert len(filtered) == 1  # deduped across the two scans
    assert filtered[0].port == 3000 and "3000/tcp filtered" in filtered[0].title
    assert "revisit" in filtered[0].detail.lower()


def test_parse_port_line_records_state() -> None:
    from oscprecon.modules.nmap import parse_port_line

    open_tcp = parse_port_line("80/tcp open  http    Apache httpd 2.4.62")
    assert open_tcp is not None and open_tcp.state == "open"
    # nmap marks a non-responding UDP port "open|filtered" — record it so downstream can tell it
    # apart from a confirmed-open service (it must not count as a strong "present" signal).
    of_udp = parse_port_line("139/udp open|filtered netbios-ssn")
    assert of_udp is not None and of_udp.state == "open|filtered"
    open_udp = parse_port_line("161/udp open          snmp")
    assert open_udp is not None and open_udp.state == "open"


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
