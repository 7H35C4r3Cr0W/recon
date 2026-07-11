from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.ike.parsers import IkeFinding, parse_ike_scan, parse_ike_tool

__all__ = [
    "IKE_SERVICE_NAMES",
    "IkeFinding",
    "IkeModule",
    "IkeStep",
    "parse_ike_scan",
    "parse_ike_tool",
]

IKE_SERVICE_NAMES = frozenset({"isakmp", "ike"})
_IKE_PORTS = frozenset({500})


@dataclass
class IkeStep:
    command: Command
    tool: str = ""  # parser key for the output, or "" when the output is not parsed


class IkeModule(Module):
    name = "ike"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in IKE_SERVICE_NAMES or s.port in _IKE_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target) -> list[IkeStep]:
        host = target.ip
        return [
            IkeStep(
                Command(
                    "ike",
                    f"ike-scan -M {host}",
                    "Detect an IKE/ISAKMP VPN responder and its main-mode transform (read-only).",
                    "< 1 min",
                    "ike/ike-scan.txt",
                ),
                "ike-scan",
            ),
            IkeStep(
                Command(
                    "ike",
                    f"ike-scan -M -A {host}",
                    "Aggressive-mode check — does the responder answer aggressive mode? (recon).",
                    "< 1 min",
                    "ike/ike-scan-aggressive.txt",
                ),
                "ike-scan-aggressive",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for kf in parse_ike_tool(tool, text):
                findings.append(
                    Finding(
                        service="ike",
                        title=f"{kf.kind}: {kf.value}",
                        detail=kf.detail,
                        fields={"kind": kf.kind, "value": kf.value, "detail": kf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        if any(f.fields.get("kind") == "aggressive" for f in findings):
            out.append(
                "IKE aggressive mode is enabled — the responder discloses PSK-related material; "
                "note it for the report (offline PSK cracking is out of scope for this recon tool)."
            )
        elif any(f.fields.get("kind") == "service" for f in findings):
            out.append(
                "IKE/ISAKMP VPN present — enumerate transforms and check whether aggressive mode "
                "is also accepted (recon)."
            )
        return out
