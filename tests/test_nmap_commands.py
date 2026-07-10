from oscprecon.models import Port, Proto, Target
from oscprecon.modules.nmap import NmapModule


def test_discovery_battery_when_no_ports() -> None:
    cmds = NmapModule().commands(Target(ip="10.10.10.5"), [])
    assert [c.output_file for c in cmds] == [
        "nmap/tcp-top1000.txt",
        "nmap/tcp-full.txt",
        "nmap/udp-top100.txt",
    ]


def test_udp_full_is_opt_in() -> None:
    cmds = NmapModule(udp_full=True).commands(Target(ip="10.10.10.5"), [])
    assert any(c.output_file == "nmap/udp-full.txt" for c in cmds)


def test_non_tcp_ports_do_not_trigger_rediscovery() -> None:
    # regression: a follow-up call with no TCP ports must NOT collapse to the discovery battery
    cmds = NmapModule().commands(Target(ip="10.10.10.5"), [Port(number=161, proto=Proto.UDP)])
    assert cmds == []


def test_versioned_scan_on_tcp_ports() -> None:
    ports = [Port(number=22, proto=Proto.TCP), Port(number=80, proto=Proto.TCP)]
    cmds = NmapModule().commands(Target(ip="10.10.10.5"), ports)
    assert len(cmds) == 1
    assert "-sV -sC -p 22,80" in cmds[0].shell_line
    assert cmds[0].output_file == "nmap/tcp-versioned.txt"
