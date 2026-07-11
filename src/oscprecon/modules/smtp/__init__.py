from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.smtp.parsers import SmtpFinding, parse_nmap_smtp, parse_smtp_tool

__all__ = [
    "SMTP_SERVICE_NAMES",
    "SmtpFinding",
    "SmtpModule",
    "SmtpStep",
    "parse_nmap_smtp",
    "parse_smtp_tool",
]

SMTP_SERVICE_NAMES = frozenset({"smtp", "smtps", "submission"})
_SMTP_PORTS = frozenset({25, 465, 587})


@dataclass
class SmtpStep:
    command: Command
    tool: str = ""  # parser key for the output, or "" when the output is not parsed


class SmtpModule(Module):
    name = "smtp"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in SMTP_SERVICE_NAMES or s.port in _SMTP_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 25) -> list[SmtpStep]:
        host = target.ip
        return [
            SmtpStep(
                Command(
                    "smtp",
                    f"nmap -sV --script smtp-commands,smtp-open-relay,smtp-ntlm-info "
                    f"-p {port} {host}",
                    "Banner, supported verbs (VRFY/EXPN), open-relay test, and NTLM domain leak.",
                    "< 1 min",
                    "smtp/nmap-smtp.txt",
                ),
                "nmap-smtp",
            )
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for sf in parse_smtp_tool(tool, text):
                findings.append(
                    Finding(
                        service="smtp",
                        title=f"{sf.kind}: {sf.value}",
                        detail=sf.detail,
                        fields={"kind": sf.kind, "value": sf.value, "detail": sf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        verbs = {f.fields.get("value", "") for f in findings if f.fields.get("kind") == "verb"}
        if verbs & {"VRFY", "EXPN"}:
            enabled = ", ".join(sorted(verbs & {"VRFY", "EXPN"}))
            out.append(
                f"{enabled} enabled — enumerate valid users by hand (nc/telnet, Tier-2); "
                "usernames feed SMB/SSH/kerberos."
            )
        if any(
            f.fields.get("kind") == "open-relay" and f.fields.get("value") == "allowed"
            for f in findings
        ):
            out.append(
                "SMTP open relay — can send mail as anyone; note it for the report (not exploited)."
            )
        ntlm = [f.fields.get("value", "") for f in findings if f.fields.get("kind") == "ntlm"]
        if ntlm:
            out.append(f"SMTP NTLM leak — {ntlm[0]} (domain/host disclosed without auth).")
        return out
