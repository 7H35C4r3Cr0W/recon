from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.jetdirect.parsers import (
    JetdirectFinding,
    parse_jetdirect_info,
    parse_jetdirect_tool,
)

__all__ = [
    "JETDIRECT_SERVICE_NAMES",
    "JetdirectFinding",
    "JetdirectModule",
    "JetdirectStep",
    "parse_jetdirect_info",
    "parse_jetdirect_tool",
]

JETDIRECT_SERVICE_NAMES = frozenset({"jetdirect", "pdl-datastream", "hp-pdl-datastr"})
_JETDIRECT_PORTS = frozenset({9100})
_DEFAULT_PORT = 9100
# 9100 is the raw PDL/JetDirect print port — no read-only enum protocol, so recon is a version
# banner identifying the printer model/firmware. The real loot is the printer web admin (80/443)
# and IPP (631). Sending PJL/PostScript (PRET) is device interaction, not recon — not wrapped.


@dataclass
class JetdirectStep:
    command: Command
    tool: str = ""


class JetdirectModule(Module):
    name = "jetdirect"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in JETDIRECT_SERVICE_NAMES or s.port in _JETDIRECT_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[JetdirectStep]:
        shell_line = f"nmap -sV -p {port or _DEFAULT_PORT} {target.ip}"
        return [
            JetdirectStep(
                Command(
                    "jetdirect",
                    shell_line,
                    "Version banner — identifies the printer model/firmware on the raw 9100 port "
                    "(read-only; 9100 has no enumeration protocol).",
                    "< 30s",
                    "jetdirect/nmap-info.txt",
                ),
                "jetdirect-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for jf in parse_jetdirect_tool(tool, text):
                findings.append(
                    Finding(
                        service="jetdirect",
                        title=f"{jf.kind}: {jf.value}",
                        detail=jf.detail,
                        fields={"kind": jf.kind, "value": jf.value, "detail": jf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind") for f in findings}
        if "product" in kinds or "printer" in kinds:
            return [
                "A network printer is on 9100 — its web admin (80/443/8080) and IPP (631) commonly "
                "leak stored SMB/LDAP/email credentials and an address book. Enumerate those "
                "read-only; raw PJL/PostScript interaction (PRET) is out of scope."
            ]
        return []
