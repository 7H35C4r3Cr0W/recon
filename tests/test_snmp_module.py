import shlex
from pathlib import Path

import yaml

from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.snmp import SnmpModule

MANUAL = (
    Path(__file__).parents[1] / "src" / "oscprecon" / "modules" / "snmp" / "manual_commands.yaml"
)


def _target() -> Target:
    return Target(ip="10.10.10.180", hostname="snmp.htb")


def test_triggers() -> None:
    module = SnmpModule()
    svc = ScanResults(target=_target(), services=[DiscoveredService(161, Proto.UDP, "snmp")])
    assert module.triggers(svc) is True
    by_port = ScanResults(target=_target(), services=[DiscoveredService(161, Proto.UDP, "")])
    assert module.triggers(by_port) is True
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(other) is False


def test_discovery_and_walk_commands() -> None:
    module = SnmpModule()
    steps = module.discovery_steps(_target())
    assert [s.tool for s in steps] == ["onesixtyone", "nmap-snmp"]
    assert steps[0].command.shell_line.startswith("onesixtyone -c ")
    # the small onesixtyone-formatted community list, not the 22 KB one (§2 "small community list")
    assert "common-snmp-community-strings-onesixtyone.txt" in steps[0].command.shell_line
    assert steps[0].command.shell_line.endswith(" 10.10.10.180")
    assert (
        "snmp-processes" in steps[1].command.shell_line and "-p 161" in steps[1].command.shell_line
    )
    walk = module.walk_step(_target())
    assert walk.command.shell_line == "snmpwalk -v2c -c public 10.10.10.180"
    assert walk.tool == "snmpwalk"
    # commands() = discovery + a default public walk
    lines = [c.shell_line for c in module.commands(_target(), [])]
    assert len(lines) == 3
    for line in lines:
        assert "brute" not in line
        assert shlex.split(line)[0] in {"onesixtyone", "nmap", "snmpwalk"}


def test_walk_uses_named_community() -> None:
    walk = SnmpModule().walk_step(_target(), community="secret")
    assert walk.command.shell_line == "snmpwalk -v2c -c secret 10.10.10.180"
    assert walk.command.output_file == "snmp/snmpwalk-secret.txt"


def test_parse_and_suggest() -> None:
    module = SnmpModule()
    findings = module.parse(
        {
            "onesixtyone": "10.10.10.180 [private] Hardware: x - Software: Windows\n",
            "snmpwalk": 'iso.3.6.1.4.1.77.1.2.25.1.1.5 = STRING: "Administrator"\n'
            'HOST-RESOURCES-MIB::hrSWRunParameters.9 = STRING: "--password=hunter2"\n',
        }
    )
    joined = " ".join(module.suggest(findings)).lower()
    assert "private" in joined  # non-default community surfaced
    assert "administrator" in joined  # leaked account name
    assert "credential" in joined  # password-in-args hint
    # the secret itself never leaks into a finding or a suggestion
    assert "hunter2" not in " ".join(f"{f.title}{f.detail}" for f in findings).lower()
    assert "hunter2" not in joined


def test_suggest_quiet_on_default_only() -> None:
    module = SnmpModule()
    findings = module.parse({"onesixtyone": "10.10.10.180 [public] Software: Linux\n"})
    joined = " ".join(module.suggest(findings)).lower()
    assert "community" not in joined  # only the default 'public' — nothing to escalate


def test_manual_commands_are_recon_only() -> None:
    entries = yaml.safe_load(MANUAL.read_text(encoding="utf-8"))
    assert len(entries) >= 5
    for entry in entries:
        command = entry["command"]
        assert shlex.split(command)[0] in {"snmpwalk", "nmap", "onesixtyone"}
        assert "--passwords" not in command and "--continue-on-success" not in command
