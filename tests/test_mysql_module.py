import shlex
from pathlib import Path

import yaml

from oscprecon import shell
from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.mysql import MysqlModule

MANUAL = (
    Path(__file__).parents[1] / "src" / "oscprecon" / "modules" / "mysql" / "manual_commands.yaml"
)
_FIX = Path(__file__).parent / "fixtures" / "mysql" / "nmap-info.txt"


def _target() -> Target:
    return Target(ip="10.10.10.14")


def test_triggers_on_service_or_port() -> None:
    module = MysqlModule()
    by_name = ScanResults(target=_target(), services=[DiscoveredService(3306, Proto.TCP, "mysql")])
    by_port = ScanResults(target=_target(), services=[DiscoveredService(3306, Proto.TCP, "")])
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(by_name) is True
    assert module.triggers(by_port) is True
    assert module.triggers(other) is False


def test_tier1_is_banner_only_no_credentials() -> None:
    steps = MysqlModule().recon_steps(_target())
    assert [s.tool for s in steps] == ["mysql-info"]
    line = steps[0].command.shell_line
    argv = shlex.split(line)
    assert argv[0] == "nmap"
    # Tier-1 auto must attempt NO credential — banner NSE only (§12: default-cred checks are Tier-2)
    for banned in ("mysqluser", "mysqlpass", "mysql-empty-password", "--script-args", "-u root"):
        assert banned not in line
    assert "mysql-info" in line
    assert shell.policy_violation(argv) is None


def test_parse_and_suggest() -> None:
    findings = MysqlModule().parse({"mysql-info": _FIX.read_text(encoding="utf-8")})
    assert findings and all(f.service == "mysql" for f in findings)
    tips = MysqlModule().suggest(findings)
    assert any("Tier-2" in tip for tip in tips)


def test_suggest_no_findings_is_empty() -> None:
    assert MysqlModule().suggest([]) == []


def test_manual_commands_are_tier2_legal() -> None:
    entries = yaml.safe_load(MANUAL.read_text(encoding="utf-8"))
    assert len(entries) >= 5
    for entry in entries:
        command = entry["command"]
        assert shlex.split(command)[0] in {"nmap", "mysql"}
        low = command.lower()
        # no file-write / arbitrary-read / OS-exec SQL primitives and no list-driven spray
        for danger in ("into outfile", "load_file", "sys_exec", "\\!"):
            assert danger not in low
        resolved = (
            command.replace("{target}", "10.10.10.14")
            .replace("{port}", "3306")
            .replace("{user}", "root")
            .replace("{password}", "P@ss")
        )
        assert shell.policy_violation(shlex.split(resolved)) is None
