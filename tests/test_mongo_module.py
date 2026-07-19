import shlex
from pathlib import Path

import yaml

from oscprecon import shell
from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.mongodb import MongoDbModule

MANUAL = (
    Path(__file__).parents[1] / "src" / "oscprecon" / "modules" / "mongodb" / "manual_commands.yaml"
)

# read-only enum verbs only — never a write/admin mutation
_WRITE_VERBS = (
    "insert",
    "update",
    "remove",
    "drop",
    ".save(",
    "createUser",
    "findAndModify",
    "deleteOne",
    "deleteMany",
    "$out",
)


def _target() -> Target:
    return Target(ip="10.10.10.14")


def test_triggers_on_service_or_port() -> None:
    module = MongoDbModule()
    by_name = ScanResults(
        target=_target(), services=[DiscoveredService(27017, Proto.TCP, "mongodb")]
    )
    by_alias = ScanResults(
        target=_target(), services=[DiscoveredService(27017, Proto.TCP, "mongod")]
    )
    by_port = ScanResults(target=_target(), services=[DiscoveredService(27017, Proto.TCP, "")])
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(by_name) is True
    assert module.triggers(by_alias) is True
    assert module.triggers(by_port) is True
    assert module.triggers(other) is False


def test_recon_steps_are_readonly_nmap_nse_and_policy_clean() -> None:
    # Tier-1 uses nmap NSE (no external client, works on the old wire-v6 servers mongosh refuses).
    steps = MongoDbModule().recon_steps(_target())
    assert [s.tool for s in steps] == ["mongodb-nmap"]
    for step in steps:
        argv = shlex.split(step.command.shell_line)
        assert argv[0] == "nmap"
        assert "--script" in argv
        assert "mongodb-info,mongodb-databases" in argv
        assert not any(verb in step.command.shell_line for verb in _WRITE_VERBS)
        # each auto command passes the exec policy at the shell chokepoint
        assert shell.policy_violation(argv) is None


def test_parse_produces_access_and_version() -> None:
    module = MongoDbModule()
    findings = module.parse(
        {
            "mongodb-version": "4.4.6\n",
            "mongodb-databases": "DB admin\nDB local\nDB reporting\n",
        }
    )
    kinds = {f.fields.get("kind") for f in findings}
    assert "access" in kinds and "version" in kinds and "database" in kinds
    assert all(f.service == "mongodb" for f in findings)


def test_suggest_on_unauth_and_wire_mismatch() -> None:
    module = MongoDbModule()
    unauth = module.parse({"mongodb-databases": "DB admin\nDB reporting\n"})
    assert any("unauthenticated" in tip for tip in module.suggest(unauth))
    wire = module.parse(
        {"mongodb-databases": "reports maximum wire version 6, requires at least 7\n"}
    )
    assert any("legacy" in tip for tip in module.suggest(wire))


def test_manual_commands_are_recon_only() -> None:
    entries = yaml.safe_load(MANUAL.read_text(encoding="utf-8"))
    assert len(entries) >= 5
    for entry in entries:
        command = entry["command"]
        assert shlex.split(command)[0] in {"mongosh", "mongo"}
        assert not any(verb in command for verb in _WRITE_VERBS)
        # placeholders resolve to a policy-clean argv (no forbidden flags smuggled in)
        resolved = command.replace("{target}", "10.10.10.14").replace("{port}", "27017")
        assert shell.policy_violation(shlex.split(resolved)) is None


def test_version_parser_rejects_ip_octets() -> None:
    # regression: a dotted IP in the output was matched as a MongoDB version ("10.10.10")
    from oscprecon.modules.mongodb.parsers import parse_mongo_version

    assert parse_mongo_version("Connected to 10.10.10.5 successfully") == []
    assert parse_mongo_version("bound to 192.168.1.100 port 27017") == []
    assert [f.value for f in parse_mongo_version("build version: 4.4.2")] == ["4.4.2"]
    assert [f.value for f in parse_mongo_version("MongoDB server version v3.6.3-ubuntu")] == [
        "3.6.3-ubuntu"
    ]
