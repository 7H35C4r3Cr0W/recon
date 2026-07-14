from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.pop3.parsers import (
    Pop3Finding,
    parse_pop3_info,
    parse_pop3_tool,
)

__all__ = [
    "POP3_SERVICE_NAMES",
    "Pop3Finding",
    "Pop3Module",
    "Pop3Step",
    "parse_pop3_info",
    "parse_pop3_tool",
]

POP3_SERVICE_NAMES = frozenset({"pop3", "pop3s", "ssl/pop3"})
_POP3_PORTS = frozenset({110, 995})
_DEFAULT_PORT = 110
# pop3-capabilities reads the CAPA banner (STLS, SASL mechs) and pop3-ntlm-info leaks the AD
# domain/host from an Exchange NTLM challenge. Both are pre-auth reads — no login is attempted.
_INFO_SCRIPTS = "pop3-capabilities,pop3-ntlm-info"


@dataclass
class Pop3Step:
    command: Command
    tool: str = ""


class Pop3Module(Module):
    name = "pop3"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in POP3_SERVICE_NAMES or s.port in _POP3_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[Pop3Step]:
        shell_line = f"nmap -sV -p {port or _DEFAULT_PORT} --script {_INFO_SCRIPTS} {target.ip}"
        return [
            Pop3Step(
                Command(
                    "pop3",
                    shell_line,
                    "POP3 read — capabilities (STLS, SASL mechs) + NTLM info (AD domain/host on "
                    "Exchange); read-only, no login.",
                    "< 30s",
                    "pop3/nmap-info.txt",
                ),
                "pop3-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for pf in parse_pop3_tool(tool, text):
                findings.append(
                    Finding(
                        service="pop3",
                        title=f"{pf.kind}: {pf.value}",
                        detail=pf.detail,
                        fields={"kind": pf.kind, "value": pf.value, "detail": pf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind"): f.fields.get("value", "") for f in findings}
        out: list[str] = []
        if "domain" in kinds:
            out.append(
                "POP3 NTLM leaks the AD domain (Exchange) — pivot the domain into LDAP / SMB / "
                "Kerberos enumeration."
            )
        if kinds.get("stls") == "no" and "version" in kinds:
            out.append(
                "STLS is not offered on 110 — credentials would cross the wire in cleartext; note "
                "it. Prefer the implicit-TLS port 995 for any later authorized testing."
            )
        return out
