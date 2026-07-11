import shlex
from pathlib import Path

import yaml

from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.ike import IkeModule

MANUAL = (
    Path(__file__).parents[1] / "src" / "oscprecon" / "modules" / "ike" / "manual_commands.yaml"
)


def _target() -> Target:
    return Target(ip="10.10.10.180", hostname="vpn.htb")


def test_triggers() -> None:
    module = IkeModule()
    svc = ScanResults(target=_target(), services=[DiscoveredService(500, Proto.UDP, "isakmp")])
    assert module.triggers(svc) is True
    by_port = ScanResults(target=_target(), services=[DiscoveredService(500, Proto.UDP, "")])
    assert module.triggers(by_port) is True
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(other) is False


def test_recon_step_commands() -> None:
    module = IkeModule()
    steps = module.recon_steps(_target())
    assert [s.tool for s in steps] == ["ike-scan", "ike-scan-aggressive"]
    assert steps[0].command.shell_line == "ike-scan -M 10.10.10.180"
    assert steps[1].command.shell_line == "ike-scan -M -A 10.10.10.180"
    for step in steps:
        assert shlex.split(step.command.shell_line)[0] == "ike-scan"
        assert "-P" not in shlex.split(step.command.shell_line)  # no PSK-hash capture for cracking
    assert len(module.commands(_target(), [])) == 2


def test_parse_and_suggest_aggressive() -> None:
    module = IkeModule()
    findings = module.parse(
        {"ike-scan-aggressive": "10.10.10.180\tAggressive Mode Handshake returned SA=(Enc=3DES)\n"}
    )
    joined = " ".join(module.suggest(findings)).lower()
    assert "aggressive mode" in joined
    assert "out of scope" in joined  # never suggests offline PSK cracking


def test_suggest_main_only_and_empty() -> None:
    module = IkeModule()
    main = module.parse({"ike-scan": "10.10.10.180\tMain Mode Handshake returned SA=(Enc=3DES)\n"})
    joined = " ".join(module.suggest(main)).lower()
    assert "vpn present" in joined and "aggressive mode is enabled" not in joined
    assert module.suggest(module.parse({"ike-scan": "0 returned handshake\n"})) == []


def test_manual_commands_are_recon_only() -> None:
    entries = yaml.safe_load(MANUAL.read_text(encoding="utf-8"))
    assert len(entries) >= 5
    for entry in entries:
        command = entry["command"]
        assert shlex.split(command)[0] in {"ike-scan", "nmap"}
        # no PSK-hash capture / cracking flags
        assert "-P" not in shlex.split(command) and "--pskcrack" not in command
        assert "--passwords" not in command
