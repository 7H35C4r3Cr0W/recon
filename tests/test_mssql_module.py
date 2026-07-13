import shlex
from pathlib import Path

import yaml

from oscprecon import shell
from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.mssql import MssqlModule

MANUAL = (
    Path(__file__).parents[1] / "src" / "oscprecon" / "modules" / "mssql" / "manual_commands.yaml"
)
_FIX = Path(__file__).parent / "fixtures" / "mssql" / "nmap-info.txt"


def _target() -> Target:
    return Target(ip="10.10.10.14")


def test_triggers_on_service_or_port() -> None:
    module = MssqlModule()
    by_name = ScanResults(
        target=_target(), services=[DiscoveredService(1433, Proto.TCP, "ms-sql-s")]
    )
    by_port = ScanResults(target=_target(), services=[DiscoveredService(1433, Proto.TCP, "")])
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(by_name) is True
    assert module.triggers(by_port) is True
    assert module.triggers(other) is False


def test_tier1_is_banner_only_no_credentials() -> None:
    steps = MssqlModule().recon_steps(_target())
    assert [s.tool for s in steps] == ["mssql-info"]
    line = steps[0].command.shell_line
    argv = shlex.split(line)
    assert argv[0] == "nmap"
    # Tier-1 auto must attempt NO credential — banner NSE only (§12: default-cred checks are Tier-2)
    for banned in (
        "mssql.username",
        "mssql.password",
        "ms-sql-empty-password",
        "--script-args",
        "sa:",
    ):
        assert banned not in line
    assert "ms-sql-info" in line and "ms-sql-ntlm-info" in line
    assert shell.policy_violation(argv) is None


def test_parse_and_suggest() -> None:
    findings = MssqlModule().parse({"mssql-info": _FIX.read_text(encoding="utf-8")})
    assert findings and all(f.service == "mssql" for f in findings)
    tips = MssqlModule().suggest(findings)
    assert any("Tier-2" in tip for tip in tips)
    assert any("AD domain" in tip for tip in tips)  # the AD fixture carries a domain finding


def test_suggest_no_findings_is_empty() -> None:
    assert MssqlModule().suggest([]) == []


def test_manual_commands_are_tier2_legal() -> None:
    entries = yaml.safe_load(MANUAL.read_text(encoding="utf-8"))
    assert len(entries) >= 5
    for entry in entries:
        command = entry["command"]
        assert shlex.split(command)[0] in {"nmap", "netexec", "impacket-mssqlclient"}
        # no OS-command execution (xp_cmdshell) and no list-driven spray
        assert "-x " not in command and "xp_cmdshell" not in command.lower()
        resolved = (
            command.replace("{target}", "10.10.10.14")
            .replace("{port}", "1433")
            .replace("{user}", "sa")
            .replace("{password}", "P@ss")
        )
        assert shell.policy_violation(shlex.split(resolved)) is None
