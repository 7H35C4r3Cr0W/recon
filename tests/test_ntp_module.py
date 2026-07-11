import shlex
from pathlib import Path

import yaml

from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.ntp import NtpModule

MANUAL = (
    Path(__file__).parents[1] / "src" / "oscprecon" / "modules" / "ntp" / "manual_commands.yaml"
)


def _target() -> Target:
    return Target(ip="10.10.10.180", hostname="ntp.htb")


def test_triggers() -> None:
    module = NtpModule()
    svc = ScanResults(target=_target(), services=[DiscoveredService(123, Proto.UDP, "ntp")])
    assert module.triggers(svc) is True
    by_port = ScanResults(target=_target(), services=[DiscoveredService(123, Proto.UDP, "")])
    assert module.triggers(by_port) is True
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(other) is False


def test_recon_step_commands() -> None:
    module = NtpModule()
    steps = module.recon_steps(_target())
    assert [s.tool for s in steps] == ["ntpq-readlist", "ntpq-sysinfo", "ntpdate"]
    assert steps[0].command.shell_line == "ntpq -c readlist 10.10.10.180"
    assert steps[1].command.shell_line == "ntpq -c sysinfo 10.10.10.180"
    assert steps[2].command.shell_line == "ntpdate -q 10.10.10.180"
    # ntpdate must ALWAYS carry -q so recon never adjusts the local clock
    assert "-q" in shlex.split(steps[2].command.shell_line)
    for step in steps:
        assert shlex.split(step.command.shell_line)[0] in {"ntpq", "ntpdate"}
    assert len(module.commands(_target(), [])) == 3


def test_parse_and_suggest() -> None:
    module = NtpModule()
    findings = module.parse(
        {"ntpq-readlist": 'version="ntpd 4.2.8", system="Linux/5.4.0", stratum=3\n'}
    )
    joined = " ".join(module.suggest(findings)).lower()
    assert "fingerprint" in joined
    assert "monlist" in joined


def test_manual_commands_are_recon_only() -> None:
    entries = yaml.safe_load(MANUAL.read_text(encoding="utf-8"))
    assert len(entries) >= 5
    for entry in entries:
        command = entry["command"]
        argv = shlex.split(command)
        assert argv[0] in {"ntpq", "ntpdate", "nmap"}
        # ntpdate is only ever used in query mode (-q) — it must never set the local clock
        if argv[0] == "ntpdate":
            assert "-q" in argv
        assert "--passwords" not in command
