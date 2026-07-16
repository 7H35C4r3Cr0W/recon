import shlex

from oscprecon import shell
from oscprecon.alive import build_alive_command, parse_alive


def test_build_alive_command_single_host_is_bounded() -> None:
    cmd = build_alive_command("10.10.10.5")
    assert cmd.startswith("nmap -sn")
    assert "10.10.10.5" in cmd
    assert "--host-timeout" in cmd  # a single dead host must not hang the check
    assert "-PS" in cmd and "-PA" in cmd  # TCP-ping too — beats ICMP-filtered Windows hosts


def test_build_alive_command_range_has_no_host_timeout() -> None:
    cmd = build_alive_command("10.10.5.7/24")
    assert "10.10.5.0/24" in cmd  # normalized to the network
    assert "--host-timeout" not in cmd


def test_build_alive_command_is_policy_clean() -> None:
    for target in ("10.10.10.5", "10.10.5.0/24"):
        argv = shlex.split(build_alive_command(target))
        assert argv[0] == "nmap"
        assert shell.policy_violation(argv) is None  # exam-legal host discovery


def test_parse_alive_single_up_host() -> None:
    text = (
        "Nmap scan report for 10.10.10.5\n"
        "Host is up (0.021s latency).\n"
        "Nmap done: 1 IP address (1 host up) scanned in 0.5s\n"
    )
    result = parse_alive(text)
    assert result.up is True
    assert result.count == 1
    assert result.hosts == ["10.10.10.5"]
    assert "0.021s" in result.latency


def test_parse_alive_down_host() -> None:
    text = (
        "Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn\n"
        "Nmap done: 1 IP address (0 hosts up) scanned in 3.1s\n"
    )
    result = parse_alive(text)
    assert result.up is False
    assert result.count == 0


def test_parse_alive_range_counts_multiple_hosts() -> None:
    text = (
        "Nmap scan report for 10.10.5.5\n"
        "Host is up (0.01s latency).\n"
        "Nmap scan report for dc01.corp.local (10.10.5.10)\n"
        "Host is up.\n"
        "Nmap done: 256 IP addresses (2 hosts up)\n"
    )
    result = parse_alive(text)
    assert result.count == 2
    assert set(result.hosts) == {"10.10.5.5", "10.10.5.10"}
