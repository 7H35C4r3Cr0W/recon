from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.sip.parsers import (
    SipFinding,
    parse_sip_info,
    parse_sip_tool,
)

__all__ = [
    "SIP_SERVICE_NAMES",
    "SipFinding",
    "SipModule",
    "SipStep",
    "parse_sip_info",
    "parse_sip_tool",
]

SIP_SERVICE_NAMES = frozenset({"sip", "sip-tls"})
_SIP_PORTS = frozenset({5060, 5061})
_DEFAULT_PORT = 5060
# sip-methods lists the SIP verbs the server accepts + its Server/User-Agent banner. SIP is mostly
# UDP, so -sU is used. Extension enumeration (svwar) is list-based (Tier-3) and never wrapped here.
_INFO_SCRIPTS = "sip-methods"


@dataclass
class SipStep:
    command: Command
    tool: str = ""


class SipModule(Module):
    name = "sip"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in SIP_SERVICE_NAMES or s.port in _SIP_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[SipStep]:
        shell_line = f"nmap -sU -sV -p {port or _DEFAULT_PORT} --script {_INFO_SCRIPTS} {target.ip}"
        return [
            SipStep(
                Command(
                    "sip",
                    shell_line,
                    "SIP read — sip-methods (accepted verbs) + the Server/User-Agent banner "
                    "(read-only). UDP, so it may need a retry.",
                    "< 1 min",
                    "sip/nmap-info.txt",
                ),
                "sip-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for sf in parse_sip_tool(tool, text):
                findings.append(
                    Finding(
                        service="sip",
                        title=f"{sf.kind}: {sf.value}",
                        detail=sf.detail,
                        fields={"kind": sf.kind, "value": sf.value, "detail": sf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind") for f in findings}
        if "methods" in kinds or "server" in kinds:
            return [
                "SIP is live — note the server/User-Agent and accepted methods. Extension "
                "enumeration (svwar) is list-based and out of scope for this recon tool."
            ]
        return []
