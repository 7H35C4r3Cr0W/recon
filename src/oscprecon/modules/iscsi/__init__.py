from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.iscsi.parsers import (
    IscsiFinding,
    parse_iscsi_targets,
    parse_iscsi_tool,
)

__all__ = [
    "ISCSI_SERVICE_NAMES",
    "IscsiFinding",
    "IscsiModule",
    "IscsiStep",
    "parse_iscsi_targets",
    "parse_iscsi_tool",
]

ISCSI_SERVICE_NAMES = frozenset({"iscsi", "iscsi-target"})
_ISCSI_PORTS = frozenset({3260})
_DEFAULT_PORT = 3260
# SendTargets discovery + nmap iscsi-info enumerate exported iSCSI targets (IQNs) read-only. Logging
# into / mounting a LUN is an explicit follow-up, never issued here.


@dataclass
class IscsiStep:
    command: Command
    tool: str = ""


class IscsiModule(Module):
    name = "iscsi"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in ISCSI_SERVICE_NAMES or s.port in _ISCSI_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[IscsiStep]:
        host = target.ip
        port_n = port or _DEFAULT_PORT
        return [
            IscsiStep(
                Command(
                    "iscsi",
                    f"iscsiadm -m discovery -t st -p {host}:{port_n}",
                    "SendTargets discovery — exported iSCSI targets/LUNs (read-only).",
                    "< 30s",
                    "iscsi/discovery.txt",
                ),
                "iscsi-discovery",
            ),
            IscsiStep(
                Command(
                    "iscsi",
                    f"nmap -sV -p {port_n} --script iscsi-info {host}",
                    "nmap iscsi-info — targets + whether authentication is required (read-only).",
                    "< 30s",
                    "iscsi/nmap-info.txt",
                ),
                "iscsi-nmap",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        seen: set[tuple[str, str]] = set()
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for isf in parse_iscsi_tool(tool, text):
                if (isf.kind, isf.value) in seen:
                    continue
                seen.add((isf.kind, isf.value))
                findings.append(
                    Finding(
                        service="iscsi",
                        title=f"{isf.kind}: {isf.value}",
                        detail=isf.detail,
                        fields={"kind": isf.kind, "value": isf.value, "detail": isf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        targets = [f.fields.get("value", "") for f in findings if f.fields.get("kind") == "target"]
        if targets:
            return [
                f"{len(targets)} iSCSI target(s) discovered — a target with no CHAP can be logged "
                "into and mounted read-only; that login is an explicit follow-up, not run here."
            ]
        return []
