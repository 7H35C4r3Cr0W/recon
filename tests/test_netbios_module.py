import shlex
from pathlib import Path

import yaml

from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.netbios import NetbiosModule

MANUAL = (
    Path(__file__).parents[1] / "src" / "oscprecon" / "modules" / "netbios" / "manual_commands.yaml"
)


def _target() -> Target:
    return Target(ip="10.10.10.180", hostname="dc.htb")


def test_triggers() -> None:
    module = NetbiosModule()
    svc = ScanResults(target=_target(), services=[DiscoveredService(137, Proto.UDP, "netbios-ns")])
    assert module.triggers(svc) is True
    by_port = ScanResults(target=_target(), services=[DiscoveredService(137, Proto.UDP, "")])
    assert module.triggers(by_port) is True
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(other) is False


def test_recon_step_commands() -> None:
    module = NetbiosModule()
    steps = module.recon_steps(_target())
    assert [s.tool for s in steps] == ["nmblookup", "nbtscan"]
    assert steps[0].command.shell_line == "nmblookup -A 10.10.10.180"
    assert steps[1].command.shell_line == "nbtscan 10.10.10.180"
    for step in steps:
        assert shlex.split(step.command.shell_line)[0] in {"nmblookup", "nbtscan"}
    assert len(module.commands(_target(), [])) == 2


def test_parse_and_suggest() -> None:
    module = NetbiosModule()
    findings = module.parse(
        {
            "nmblookup": "\tSRV01    <20> -         M <ACTIVE>\n"
            "\tMYDOMAIN <1c> - <GROUP> M <ACTIVE>\n"
            "\tADMINPC  <03> -         M <ACTIVE>\n"
        }
    )
    joined = " ".join(module.suggest(findings)).lower()
    assert "domain controller" in joined  # <1c>
    assert "smb file server" in joined  # <20>
    assert "adminpc" in joined  # <03> user


def test_suggest_quiet_when_nothing_notable() -> None:
    module = NetbiosModule()
    findings = module.parse({"nmblookup": "\tHOST <00> -         M <ACTIVE>\n"})
    assert module.suggest(findings) == []  # a lone workstation name — nothing to escalate


def test_manual_commands_are_recon_only() -> None:
    entries = yaml.safe_load(MANUAL.read_text(encoding="utf-8"))
    assert len(entries) >= 5
    for entry in entries:
        command = entry["command"]
        assert shlex.split(command)[0] in {"nmblookup", "nbtscan", "nmap"}
        assert "--passwords" not in command and "brute" not in command
