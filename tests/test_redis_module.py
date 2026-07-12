import shlex
from pathlib import Path

import yaml

from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.redis import RedisModule

MANUAL = (
    Path(__file__).parents[1] / "src" / "oscprecon" / "modules" / "redis" / "manual_commands.yaml"
)


def _target() -> Target:
    return Target(ip="10.10.10.160")


def test_triggers_on_service_or_port() -> None:
    module = RedisModule()
    by_name = ScanResults(target=_target(), services=[DiscoveredService(6379, Proto.TCP, "redis")])
    by_port = ScanResults(target=_target(), services=[DiscoveredService(6379, Proto.TCP, "")])
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(by_name) is True
    assert module.triggers(by_port) is True
    assert module.triggers(other) is False


def test_recon_steps_are_readonly_redis_cli() -> None:
    steps = RedisModule().recon_steps(_target())
    assert [s.tool for s in steps] == ["redis-info", "redis-config", "redis-clients"]
    for step in steps:
        argv = shlex.split(step.command.shell_line)
        assert argv[0] == "redis-cli"
        # read-only verbs only — never SET/CONFIG SET/FLUSH/EVAL
        assert not any(
            w in step.command.shell_line for w in ("SET ", "FLUSH", "EVAL", "MODULE LOAD")
        )


def test_parse_produces_findings() -> None:
    module = RedisModule()
    findings = module.parse({"redis-info": "redis_version:7.0.0\nrole:master\nos:Linux\n"})
    kinds = {f.fields.get("kind") for f in findings}
    assert "access" in kinds and "version" in kinds


def test_suggest_on_unauth() -> None:
    module = RedisModule()
    findings = module.parse({"redis-info": "redis_version:7.0.0\nrole:master\n"})
    tips = module.suggest(findings)
    assert any("unauthenticated" in t for t in tips)


def test_manual_commands_are_recon_only() -> None:
    entries = yaml.safe_load(MANUAL.read_text(encoding="utf-8"))
    assert len(entries) >= 5
    for entry in entries:
        command = entry["command"]
        assert shlex.split(command)[0] == "redis-cli"
        assert "FLUSH" not in command and "SET " not in command  # no destructive writes
