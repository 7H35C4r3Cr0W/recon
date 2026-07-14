from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.ajp.parsers import (
    AjpFinding,
    parse_ajp_info,
    parse_ajp_tool,
)
from oscprecon.modules.base import Module

__all__ = [
    "AJP_SERVICE_NAMES",
    "AjpFinding",
    "AjpModule",
    "AjpStep",
    "parse_ajp_info",
    "parse_ajp_tool",
]

AJP_SERVICE_NAMES = frozenset({"ajp13", "ajp"})
_AJP_PORTS = frozenset({8009})
_DEFAULT_PORT = 8009
# ajp-methods lists the HTTP methods the AJP13 connector accepts; ajp-headers dumps its response
# headers (Server banner). Both are read-only — no request is made that changes server state.
_INFO_SCRIPTS = "ajp-methods,ajp-headers"


@dataclass
class AjpStep:
    command: Command
    tool: str = ""


class AjpModule(Module):
    name = "ajp"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in AJP_SERVICE_NAMES or s.port in _AJP_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[AjpStep]:
        shell_line = f"nmap -sV -p {port or _DEFAULT_PORT} --script {_INFO_SCRIPTS} {target.ip}"
        return [
            AjpStep(
                Command(
                    "ajp",
                    shell_line,
                    "AJP13 read — ajp-methods (allowed HTTP methods) + ajp-headers (Server banner) "
                    "on the Tomcat AJP connector (read-only).",
                    "< 30s",
                    "ajp/nmap-info.txt",
                ),
                "ajp-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for af in parse_ajp_tool(tool, text):
                findings.append(
                    Finding(
                        service="ajp",
                        title=f"{af.kind}: {af.value}",
                        detail=af.detail,
                        fields={"kind": af.kind, "value": af.value, "detail": af.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        kinds = {f.fields.get("kind") for f in findings}
        if "methods" in kinds or "server" in kinds:
            out.append(
                "AJP13 connector is live — enumerate the paired Tomcat HTTP connector (usually "
                "8080) for /manager and app paths; AJP fronts the same webapps."
            )
        if "risky" in kinds:
            out.append(
                "AJP exposes write-ish methods (PUT/DELETE) — note it; confirm on the HTTP "
                "connector whether they are actually honoured (read-only recon)."
            )
        return out
