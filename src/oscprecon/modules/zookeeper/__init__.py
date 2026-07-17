from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.zookeeper.parsers import (
    ZookeeperFinding,
    parse_nmap_zookeeper,
    parse_zk_4lw,
    parse_zookeeper_tool,
)

__all__ = [
    "ZOOKEEPER_SERVICE_NAMES",
    "ZookeeperFinding",
    "ZookeeperModule",
    "ZookeeperStep",
    "parse_nmap_zookeeper",
    "parse_zk_4lw",
    "parse_zookeeper_tool",
]

ZOOKEEPER_SERVICE_NAMES = frozenset({"zookeeper"})
_ZOOKEEPER_PORTS = frozenset({2181})
_DEFAULT_PORT = 2181


@dataclass
class ZookeeperStep:
    command: Command
    tool: str = ""


class ZookeeperModule(Module):
    name = "zookeeper"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in ZOOKEEPER_SERVICE_NAMES or s.port in _ZOOKEEPER_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[ZookeeperStep]:
        p = port or _DEFAULT_PORT
        return [
            ZookeeperStep(
                Command(
                    "zookeeper",
                    f"nmap -sV -p {p} {target.ip}",
                    "Confirm ZooKeeper + version on 2181 (banner). The 4lw stat commands "
                    "(mntr / stat / conf) are Tier-2 follow-ups — nc is copy-to-a-terminal only.",
                    "< 30s",
                    "zookeeper/nmap-sv.txt",
                ),
                "nmap-zookeeper",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for zf in parse_zookeeper_tool(tool, text):
                findings.append(
                    Finding(
                        service="zookeeper",
                        title=f"{zf.kind}: {zf.value}",
                        detail=zf.detail,
                        fields={"kind": zf.kind, "value": zf.value, "detail": zf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind") for f in findings}
        if "access" in kinds or "version" in kinds:
            return [
                "ZooKeeper answers on 2181 — run the 4-letter-word commands (`conf`, `envi`, "
                "`mntr`) read-only by copying the nc lines to a terminal; dataDir / env often leak "
                "service topology and credentials. Read-only only — never `set` / `rmr` / `create`."
            ]
        return []
