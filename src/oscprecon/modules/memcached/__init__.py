from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.memcached.parsers import (
    MemcachedFinding,
    parse_memcached_info,
    parse_memcached_tool,
)

__all__ = [
    "MEMCACHED_SERVICE_NAMES",
    "MemcachedFinding",
    "MemcachedModule",
    "MemcachedStep",
    "parse_memcached_info",
    "parse_memcached_tool",
]

MEMCACHED_SERVICE_NAMES = frozenset({"memcache", "memcached"})
_MEMCACHED_PORTS = frozenset({11211})
_DEFAULT_PORT = 11211
# memcached-info issues the stats commands over the text protocol read-only (the native nc/memcstat
# clients are not on the allowed toolset). Classic memcached is unauthenticated by design.
_INFO_SCRIPTS = "memcached-info"


@dataclass
class MemcachedStep:
    command: Command
    tool: str = ""


class MemcachedModule(Module):
    name = "memcached"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in MEMCACHED_SERVICE_NAMES or s.port in _MEMCACHED_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[MemcachedStep]:
        shell_line = f"nmap -sV -p {port or _DEFAULT_PORT} --script {_INFO_SCRIPTS} {target.ip}"
        return [
            MemcachedStep(
                Command(
                    "memcached",
                    shell_line,
                    "memcached-info — version, item/connection counts, slab stats over the text "
                    "protocol (unauth read-only).",
                    "< 30s",
                    "memcached/nmap-info.txt",
                ),
                "memcached-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for mf in parse_memcached_tool(tool, text):
                findings.append(
                    Finding(
                        service="memcached",
                        title=f"{mf.kind}: {mf.value}",
                        detail=mf.detail,
                        fields={"kind": mf.kind, "value": mf.value, "detail": mf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind"): f.fields.get("value", "") for f in findings}
        if kinds.get("access") == "unauth" and kinds.get("items", "0") not in ("", "0"):
            return [
                "Memcached answers unauthenticated and holds cached items — enumerate slabs/keys "
                "read-only (`nmap --script memcached-info`); cached data may contain secrets."
            ]
        if kinds.get("access") == "unauth":
            return [
                "Memcached answers unauthenticated — note the version; no items are cached yet."
            ]
        return []
