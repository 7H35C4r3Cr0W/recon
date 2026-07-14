from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.imap.parsers import (
    ImapFinding,
    parse_imap_info,
    parse_imap_tool,
)

__all__ = [
    "IMAP_SERVICE_NAMES",
    "ImapFinding",
    "ImapModule",
    "ImapStep",
    "parse_imap_info",
    "parse_imap_tool",
]

IMAP_SERVICE_NAMES = frozenset({"imap", "imaps", "ssl/imap"})
_IMAP_PORTS = frozenset({143, 993})
_DEFAULT_PORT = 143
# imap-capabilities reads the CAPABILITY banner (STARTTLS, auth mechs) and imap-ntlm-info leaks the
# AD domain/host from an Exchange NTLM challenge. Both are pre-auth reads — no login is attempted.
_INFO_SCRIPTS = "imap-capabilities,imap-ntlm-info"


@dataclass
class ImapStep:
    command: Command
    tool: str = ""


class ImapModule(Module):
    name = "imap"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in IMAP_SERVICE_NAMES or s.port in _IMAP_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[ImapStep]:
        shell_line = f"nmap -sV -p {port or _DEFAULT_PORT} --script {_INFO_SCRIPTS} {target.ip}"
        return [
            ImapStep(
                Command(
                    "imap",
                    shell_line,
                    "IMAP read — capabilities (STARTTLS, auth mechs) + NTLM info (AD domain/host "
                    "on Exchange); read-only, no login.",
                    "< 30s",
                    "imap/nmap-info.txt",
                ),
                "imap-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for imf in parse_imap_tool(tool, text):
                findings.append(
                    Finding(
                        service="imap",
                        title=f"{imf.kind}: {imf.value}",
                        detail=imf.detail,
                        fields={"kind": imf.kind, "value": imf.value, "detail": imf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind"): f.fields.get("value", "") for f in findings}
        out: list[str] = []
        if "domain" in kinds:
            out.append(
                "IMAP NTLM leaks the AD domain (Exchange) — pivot the domain into LDAP / SMB / "
                "Kerberos enumeration."
            )
        if kinds.get("starttls") == "no" and "version" in kinds:
            out.append(
                "STARTTLS is not offered on 143 — credentials would cross the wire in cleartext; "
                "note it. Prefer the implicit-TLS port 993 for any later authorized testing."
            )
        return out
