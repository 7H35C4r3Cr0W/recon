import shlex
from pathlib import Path

import yaml

from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.tftp import COMMON_FILES, TftpModule, tftp_get_url

MANUAL = (
    Path(__file__).parents[1] / "src" / "oscprecon" / "modules" / "tftp" / "manual_commands.yaml"
)


def _target() -> Target:
    return Target(ip="10.10.10.180", hostname="tftp.htb")


def test_triggers() -> None:
    module = TftpModule()
    svc = ScanResults(target=_target(), services=[DiscoveredService(69, Proto.UDP, "tftp")])
    assert module.triggers(svc) is True
    by_port = ScanResults(target=_target(), services=[DiscoveredService(69, Proto.UDP, "")])
    assert module.triggers(by_port) is True
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(other) is False


def test_commands_are_enum_plus_gets() -> None:
    module = TftpModule()
    assert module.enum_step(_target()).command.shell_line == (
        "nmap -sU -sV --script tftp-enum -p 69 10.10.10.180"
    )
    lines = [c.shell_line for c in module.commands(_target(), [])]
    assert len(lines) == 1 + len(COMMON_FILES)  # one enum + one GET per well-known file
    assert lines[0].startswith("nmap ")
    for line in lines[1:]:
        assert line.startswith("curl -s tftp://10.10.10.180/")
    for line in lines:
        assert "brute" not in line
        assert shlex.split(line)[0] in {"nmap", "curl"}
        assert " -T " not in line and "put" not in line.lower()  # never upload


def test_get_url_encodes_hostile_filename() -> None:
    # a filename from tftp-enum output is target-controlled — it must not smuggle a flag or 2nd URL
    step = TftpModule().get_step(_target(), "x -o /etc/evil ")
    argv = shlex.split(step.command.shell_line)
    assert argv[0] == "curl"
    # exactly one URL argument; the injected "-o"/path never appears as its own token
    urls = [a for a in argv if a.startswith("tftp://")]
    assert len(urls) == 1
    assert "/etc/evil" not in argv
    assert "-o" not in argv[2:]


def test_get_url_encoding() -> None:
    assert tftp_get_url("10.0.0.1", 69, "a b") == "tftp://10.0.0.1/a%20b"
    assert tftp_get_url("10.0.0.1", 6969, "cfg") == "tftp://10.0.0.1:6969/cfg"


def test_parse_and_suggest() -> None:
    module = TftpModule()
    findings = module.parse({"nmap-tftp": "| tftp-enum:\n|_  running-config\n"})
    joined = " ".join(module.suggest(findings)).lower()
    assert "running-config" in joined
    assert "secret" in joined  # nudges inspecting the config for creds


def test_manual_commands_are_read_only() -> None:
    entries = yaml.safe_load(MANUAL.read_text(encoding="utf-8"))
    assert len(entries) >= 5
    for entry in entries:
        command = entry["command"]
        assert shlex.split(command)[0] in {"nmap", "curl", "tftp", "atftp"}
        # never an upload/PUT anywhere in the follow-ups
        assert "--put" not in command and " put " not in f" {command} " and "-p FILE" not in command
        assert "--passwords" not in command
