from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.redis.parsers import (
    RedisFinding,
    parse_redis_clients,
    parse_redis_config,
    parse_redis_info,
    parse_redis_tool,
)

__all__ = [
    "REDIS_SERVICE_NAMES",
    "RedisFinding",
    "RedisModule",
    "RedisStep",
    "parse_redis_clients",
    "parse_redis_config",
    "parse_redis_info",
    "parse_redis_tool",
]

REDIS_SERVICE_NAMES = frozenset({"redis"})
_REDIS_PORTS = frozenset({6379})
_DEFAULT_PORT = 6379


@dataclass
class RedisStep:
    command: Command
    tool: str = ""


class RedisModule(Module):
    name = "redis"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in REDIS_SERVICE_NAMES or s.port in _REDIS_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target) -> list[RedisStep]:
        host = target.ip
        port = _DEFAULT_PORT
        base = f"redis-cli -h {host} -p {port}"
        return [
            RedisStep(
                Command(
                    "redis",
                    f"{base} INFO",
                    "Unauth INFO — server version, role, OS, whether auth is required (read-only).",
                    "< 30s",
                    "redis/info.txt",
                ),
                "redis-info",
            ),
            RedisStep(
                Command(
                    "redis",
                    f"{base} CONFIG GET *",
                    "Unauth running config — leaks requirepass, dir, dbfilename, bind (read-only).",
                    "< 30s",
                    "redis/config.txt",
                ),
                "redis-config",
            ),
            RedisStep(
                Command(
                    "redis",
                    f"{base} CLIENT LIST",
                    "Unauth CLIENT LIST — currently-connected clients (read-only).",
                    "< 30s",
                    "redis/clients.txt",
                ),
                "redis-clients",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for rf in parse_redis_tool(tool, text):
                findings.append(
                    Finding(
                        service="redis",
                        title=f"{rf.kind}: {rf.value}",
                        detail=rf.detail,
                        fields={"kind": rf.kind, "value": rf.value, "detail": rf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        kinds = {f.fields.get("kind"): f.fields.get("value", "") for f in findings}
        if kinds.get("access") == "unauth":
            out.append(
                "Redis answers unauthenticated — enumerate keys with `redis-cli --scan` (bounded) "
                "and note CONFIG dir/dbfilename; requirepass=<empty> confirms no password is set."
            )
        if kinds.get("access") == "auth-required":
            out.append(
                "Redis requires auth — try single default checks (empty / 'foobared') as Tier-2."
            )
        return out
