from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.netbios.parsers import (
    NetbiosFinding,
    parse_nbtscan,
    parse_netbios_tool,
    parse_nmblookup,
)

__all__ = [
    "NETBIOS_SERVICE_NAMES",
    "NetbiosFinding",
    "NetbiosModule",
    "NetbiosStep",
    "parse_nbtscan",
    "parse_netbios_tool",
    "parse_nmblookup",
]

NETBIOS_SERVICE_NAMES = frozenset({"netbios-ns", "netbios", "nbt", "netbios-ssn"})
_NETBIOS_PORTS = frozenset({137})


@dataclass
class NetbiosStep:
    command: Command
    tool: str = ""  # parser key for the output, or "" when the output is not parsed


class NetbiosModule(Module):
    name = "netbios"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in NETBIOS_SERVICE_NAMES or s.port in _NETBIOS_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target) -> list[NetbiosStep]:
        host = target.ip
        return [
            NetbiosStep(
                Command(
                    "netbios",
                    f"nmblookup -A {host}",
                    "Query the NetBIOS name table — host, domain, roles, MAC (read-only).",
                    "< 30s",
                    "netbios/nmblookup-A.txt",
                ),
                "nmblookup",
            ),
            NetbiosStep(
                Command(
                    "netbios",
                    f"nbtscan {host}",
                    "NetBIOS scan — name + server flag + MAC in one line (read-only).",
                    "< 30s",
                    "netbios/nbtscan.txt",
                ),
                "nbtscan",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for nf in parse_netbios_tool(tool, text):
                findings.append(
                    Finding(
                        service="netbios",
                        title=f"{nf.kind}: {nf.value}",
                        detail=nf.detail,
                        fields={"kind": nf.kind, "value": nf.value, "detail": nf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        roles = {f.fields.get("value", "") for f in findings if f.fields.get("kind") == "role"}
        domains = [f.fields.get("value", "") for f in findings if f.fields.get("kind") == "domain"]
        if any("domain-controllers" in r or "PDC" in r for r in roles):
            dom = f" ({domains[0]})" if domains else ""
            out.append(
                f"NetBIOS shows a Domain Controller / AD domain{dom} — pivot to the LDAP, "
                "kerberos (GetNPUsers/GetUserSPNs) and SMB AD-enum flows."
            )
        if any("file-server" in r for r in roles):
            out.append(
                "SMB file server present (<20>) — run the SMB module (null session / shares)."
            )
        users = [f.fields.get("value", "") for f in findings if f.fields.get("kind") == "user"]
        if users:
            out.append(
                f"NetBIOS <03> name '{users[0]}' — a possible logged-in user; "
                "feed it to SMB / kerberos user enumeration."
            )
        return out
