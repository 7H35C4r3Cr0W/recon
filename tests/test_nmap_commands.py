import shlex

from oscprecon import shell
from oscprecon.models import Port, Proto, Target
from oscprecon.modules.nmap import NmapModule

_TARGET = Target(ip="10.10.10.5")


def test_discovery_battery_when_no_ports() -> None:
    cmds = NmapModule().commands(_TARGET, [])
    assert [c.output_file for c in cmds] == [
        "nmap/tcp-top1000.txt",
        "nmap/tcp-full.txt",
        "nmap/udp-top100.txt",
    ]


def test_default_profile_matches_bare_default() -> None:
    # regression: 'default' must stay byte-identical to the historical battery
    assert [c.shell_line for c in NmapModule(scan_profile="default").commands(_TARGET, [])] == [
        c.shell_line for c in NmapModule().commands(_TARGET, [])
    ]


def test_udp_full_is_opt_in_and_deferred() -> None:
    module = NmapModule(udp_full=True)
    # udp -p- is NOT in the discovery battery (it must not block the versioned scan)...
    assert all(c.output_file != "nmap/udp-full.txt" for c in module.commands(_TARGET, []))
    # ...it is a deferred command the orchestrator runs LAST, after -sV -sC
    assert [c.output_file for c in module.deferred_commands(_TARGET)] == ["nmap/udp-full.txt"]
    # without the opt-in and not the `full` profile, there is no udp-full at all
    assert NmapModule().deferred_commands(_TARGET) == []


def test_quick_profile_is_top1000_only() -> None:
    cmds = NmapModule(scan_profile="quick").commands(_TARGET, [])
    assert [c.output_file for c in cmds] == ["nmap/tcp-top1000.txt"]
    assert "-T4" in cmds[0].shell_line  # speed-tuned
    # quick never runs UDP, even if udp_full is set
    cmds_udp = NmapModule(udp_full=True, scan_profile="quick").commands(_TARGET, [])
    assert [c.output_file for c in cmds_udp] == ["nmap/tcp-top1000.txt"]


def test_exam_profile_is_tight_fast_and_exam_legal() -> None:
    cmds = NmapModule(scan_profile="exam").commands(_TARGET, [])
    assert [c.output_file for c in cmds] == [
        "nmap/tcp-top1000.txt",
        "nmap/tcp-full.txt",
        "nmap/udp-top100.txt",
    ]
    lines = " ".join(c.shell_line for c in cmds)
    assert "--min-rate" in lines and "-T4" in lines  # speed-tuned for exam time
    assert "--script vuln" not in lines  # exam-legal: no vuln NSE in the auto battery


def test_full_profile_defers_udp_full_after_versioned() -> None:
    module = NmapModule(scan_profile="full")  # no udp_full flag
    # `full`'s discovery battery is the same fast TCP + UDP-top100 as default — no blocking udp -p-
    assert [c.output_file for c in module.commands(_TARGET, [])] == [
        "nmap/tcp-top1000.txt",
        "nmap/tcp-full.txt",
        "nmap/udp-top100.txt",
    ]
    # what makes `full` more than `default`: it defers the full UDP sweep to run after the versioned
    assert [c.output_file for c in module.deferred_commands(_TARGET)] == ["nmap/udp-full.txt"]


def test_quick_never_runs_udp_even_deferred() -> None:
    # quick is TCP-only triage — no UDP anywhere, even with the --udp-full opt-in
    assert NmapModule(scan_profile="quick", udp_full=True).deferred_commands(_TARGET) == []


def test_unknown_profile_falls_back_to_default() -> None:
    assert [c.shell_line for c in NmapModule(scan_profile="bogus").commands(_TARGET, [])] == [
        c.shell_line for c in NmapModule(scan_profile="default").commands(_TARGET, [])
    ]


def test_every_profile_battery_passes_the_exec_policy() -> None:
    # every generated nmap line must clear the §2 allow/deny policy — recon-only, no brute/spray
    for profile in ("quick", "default", "full", "exam"):
        module = NmapModule(udp_full=True, scan_profile=profile)
        cmds = (
            module.commands(_TARGET, [])
            + module.commands(_TARGET, [Port(number=445, proto=Proto.TCP)])
            + module.deferred_commands(_TARGET)
        )
        for cmd in cmds:
            assert shell.policy_violation(shlex.split(cmd.shell_line)) is None, cmd.shell_line


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
