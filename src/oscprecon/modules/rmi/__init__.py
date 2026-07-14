from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.rmi.parsers import (
    RmiFinding,
    parse_rmi_info,
    parse_rmi_tool,
)

__all__ = [
    "RMI_SERVICE_NAMES",
    "RmiFinding",
    "RmiModule",
    "RmiStep",
    "parse_rmi_info",
    "parse_rmi_tool",
]

RMI_SERVICE_NAMES = frozenset({"java-rmi", "rmiregistry", "rmi", "ssl/java-rmi"})
# 1099 is the registry; 1098/1050 are common activation ports; the vault notes also document 1100.
_RMI_PORTS = frozenset({1099, 1100, 1098, 1050})
_DEFAULT_PORT = 1099
# rmi-dumpregistry lists the objects bound in the RMI registry (names, classes, dynamic endpoints)
# read-only. Invoking a method / deserialization exploitation runs over the endpoints — never here.
_INFO_SCRIPTS = "rmi-dumpregistry"


@dataclass
class RmiStep:
    command: Command
    tool: str = ""


class RmiModule(Module):
    name = "rmi"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in RMI_SERVICE_NAMES or s.port in _RMI_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[RmiStep]:
        shell_line = f"nmap -sV -p {port or _DEFAULT_PORT} --script {_INFO_SCRIPTS} {target.ip}"
        return [
            RmiStep(
                Command(
                    "rmi",
                    shell_line,
                    "rmi-dumpregistry — objects bound in the RMI registry + their dynamic "
                    "endpoints (read-only; no method is invoked).",
                    "< 30s",
                    "rmi/nmap-info.txt",
                ),
                "rmi-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for rf in parse_rmi_tool(tool, text):
                findings.append(
                    Finding(
                        service="rmi",
                        title=f"{rf.kind}: {rf.value}",
                        detail=rf.detail,
                        fields={"kind": rf.kind, "value": rf.value, "detail": rf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        objects = [f.fields.get("value", "") for f in findings if f.fields.get("kind") == "object"]
        if any(o.lower() == "jmxrmi" for o in objects):
            return [
                "The RMI registry exposes 'jmxrmi' (a JMX endpoint) — note it; JMX auth-check and "
                "deserialization are exploitation and out of scope for this recon tool."
            ]
        if objects:
            return [
                f"{len(objects)} object(s) bound in the RMI registry — record the names/endpoints; "
                "invoking a remote method is out of scope for this recon tool."
            ]
        return []
