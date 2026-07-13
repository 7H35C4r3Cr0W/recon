import shlex
from pathlib import Path

import yaml

from oscprecon import shell
from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.postgresql import PostgresqlModule

MANUAL = (
    Path(__file__).parents[1]
    / "src"
    / "oscprecon"
    / "modules"
    / "postgresql"
    / "manual_commands.yaml"
)
_FIX = Path(__file__).parent / "fixtures" / "postgresql" / "nmap-sv.txt"


def _target() -> Target:
    return Target(ip="10.10.10.14")


def test_triggers_on_service_or_port() -> None:
    module = PostgresqlModule()
    by_name = ScanResults(
        target=_target(), services=[DiscoveredService(5432, Proto.TCP, "postgresql")]
    )
    by_port = ScanResults(target=_target(), services=[DiscoveredService(5432, Proto.TCP, "")])
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(by_name) is True
    assert module.triggers(by_port) is True
    assert module.triggers(other) is False


def test_tier1_is_credential_free_version_detection() -> None:
    steps = PostgresqlModule().recon_steps(_target())
    assert [s.tool for s in steps] == ["postgresql-sv"]
    line = steps[0].command.shell_line
    argv = shlex.split(line)
    assert argv[0] == "nmap"
    assert "-sV" in argv
    # Tier-1 must attempt NO credential and NOT invent an info NSE / run the brute script
    for banned in ("-U", "postgres:", "--script", "pgsql-brute", "pgsql-info", "-c "):
        assert banned not in line
    assert shell.policy_violation(argv) is None


def test_non_standard_port_propagates_through_command_and_output() -> None:
    steps = PostgresqlModule().recon_steps(_target(), port=5433)
    line = steps[0].command.shell_line
    assert "-p 5433" in line and "5432" not in line  # honours discovered port, no 5432 fallback
    assert steps[0].command.output_file == "postgresql/nmap-sv-5433.txt"


def test_parse_and_suggest() -> None:
    findings = PostgresqlModule().parse({"postgresql-sv": _FIX.read_text(encoding="utf-8")})
    assert findings and all(f.service == "postgresql" for f in findings)
    tips = PostgresqlModule().suggest(findings)
    assert any("Tier-2" in tip for tip in tips)


def test_suggest_no_findings_is_empty() -> None:
    assert PostgresqlModule().suggest([]) == []


def test_manual_commands_are_tier2_read_only() -> None:
    entries = yaml.safe_load(MANUAL.read_text(encoding="utf-8"))
    assert len(entries) >= 5
    for entry in entries:
        command = entry["command"]
        assert shlex.split(command)[0] == "psql"
        low = command.lower()
        # no server-modifying / file / OS primitives, no list spray, no PGPASSWORD env assignment
        for danger in (
            "into outfile",
            "copy ",
            "create ",
            "drop ",
            "alter ",
            "pg_read_file",
            "pg_write_file",
            "lo_export",
            "\\!",
            "pgpassword=",
        ):
            assert danger not in low
        resolved = (
            command.replace("{target}", "10.10.10.14")
            .replace("{port}", "5432")
            .replace("{user}", "svc")
            .replace("{password}", "P@ss")
            .replace("{database}", "postgres")
        )
        assert shell.policy_violation(shlex.split(resolved)) is None
