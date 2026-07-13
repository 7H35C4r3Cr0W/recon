from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.kerberos.parsers import (
    KerberosFinding,
    parse_getadusers,
    parse_getnpusers,
    parse_getuserspns,
    parse_kerberos_tool,
    parse_nmap_kerberos,
)

__all__ = [
    "KERBEROS_SERVICE_NAMES",
    "KerberosFinding",
    "KerberosModule",
    "KerberosStep",
    "parse_getadusers",
    "parse_getnpusers",
    "parse_getuserspns",
    "parse_kerberos_tool",
    "parse_nmap_kerberos",
]

KERBEROS_SERVICE_NAMES = frozenset({"kerberos", "kerberos-sec", "kpasswd5"})
_KERBEROS_PORTS = frozenset({88})


@dataclass
class KerberosStep:
    command: Command
    tool: str = ""  # parser key for the output, or "" when the output is not parsed


class KerberosModule(Module):
    name = "kerberos"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in KERBEROS_SERVICE_NAMES or s.port in _KERBEROS_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target) -> list[KerberosStep]:
        # Tier-1 is credential-free and single-shot: confirm the KDC + read its server time (the
        # clock-skew reference Kerberos auth depends on). User/SPN enumeration needs a domain +
        # (mostly) creds and is offered as Tier-2 manual follow-ups — never auto-run.
        host = target.ip
        return [
            KerberosStep(
                Command(
                    "kerberos",
                    f"nmap -sV -p 88 {host}",
                    "Confirm the Kerberos KDC (a Domain Controller) and read its server time.",
                    "< 1 min",
                    "kerberos/nmap-sv.txt",
                ),
                "nmap-kerberos",
            )
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for kf in parse_kerberos_tool(tool, text):
                findings.append(
                    Finding(
                        service="kerberos",
                        title=f"{kf.kind}: {kf.value}",
                        detail=kf.detail,
                        fields={"kind": kf.kind, "value": kf.value, "detail": kf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        if any(f.fields.get("kind") == "service" for f in findings):
            out.append(
                "Kerberos KDC confirmed — this host is a Domain Controller. Enumerate users (SMB "
                "RID cycling / LDAP), then AS-REP-check known users and list SPNs with valid creds."
            )
        roastable = [f.fields.get("value", "") for f in findings if f.fields.get("kind") == "spn"]
        if roastable:
            out.append(
                f"{len(roastable)} SPN(s) found — Kerberoastable accounts. Record them "
                "(requesting a ticket is enumeration; cracking is out of scope)."
            )
        return out
