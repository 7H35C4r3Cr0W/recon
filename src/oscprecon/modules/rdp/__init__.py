from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.rdp.parsers import (
    RdpFinding,
    parse_rdp_info,
    parse_rdp_tool,
)

__all__ = [
    "RDP_SERVICE_NAMES",
    "RdpFinding",
    "RdpModule",
    "RdpStep",
    "parse_rdp_info",
    "parse_rdp_tool",
]

RDP_SERVICE_NAMES = frozenset({"ms-wbt-server", "rdp", "ms-term-serv"})
_RDP_PORTS = frozenset({3389})
_DEFAULT_PORT = 3389
# rdp-ntlm-info + rdp-enum-encryption are pre-auth info leaks (read-only, no credential attempt):
# NTLM leaks the AD domain/hostname/OS build, enum-encryption reveals whether NLA (CredSSP) is
# enforced. No login is attempted here — credentialed RDP is out of scope (Spray mode only).
_INFO_SCRIPTS = "rdp-ntlm-info,rdp-enum-encryption"


@dataclass
class RdpStep:
    command: Command
    tool: str = ""


class RdpModule(Module):
    name = "rdp"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in RDP_SERVICE_NAMES or s.port in _RDP_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[RdpStep]:
        shell_line = f"nmap -sV -p {port or _DEFAULT_PORT} --script {_INFO_SCRIPTS} {target.ip}"
        return [
            RdpStep(
                Command(
                    "rdp",
                    shell_line,
                    "Unauth banner — rdp-ntlm-info leaks the AD domain/hostname/OS build; "
                    "rdp-enum-encryption shows whether NLA (CredSSP) is enforced (read-only).",
                    "< 30s",
                    "rdp/nmap-info.txt",
                ),
                "rdp-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for rf in parse_rdp_tool(tool, text):
                findings.append(
                    Finding(
                        service="rdp",
                        title=f"{rf.kind}: {rf.value}",
                        detail=rf.detail,
                        fields={"kind": rf.kind, "value": rf.value, "detail": rf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        kinds = {f.fields.get("kind"): f.fields.get("value", "") for f in findings}
        if "domain" in kinds:
            out.append(
                "RDP NTLM leaks the AD domain — this host is domain-joined; cross-reference the "
                "domain with LDAP / SMB / Kerberos enumeration."
            )
        if kinds.get("nla") == "not-enforced":
            out.append(
                "NLA is not enforced — the login screen is reachable without a prior credential. "
                "Note it; credentialed RDP access is a Spray-mode (opt-in) follow-up, never auto."
            )
        return out
