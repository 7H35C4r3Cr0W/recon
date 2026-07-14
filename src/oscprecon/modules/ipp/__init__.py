from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.ipp.parsers import (
    IppFinding,
    parse_ipp_curl,
    parse_ipp_nmap,
    parse_ipp_tool,
)

__all__ = [
    "IPP_SERVICE_NAMES",
    "IppFinding",
    "IppModule",
    "IppStep",
    "parse_ipp_curl",
    "parse_ipp_nmap",
    "parse_ipp_tool",
]

IPP_SERVICE_NAMES = frozenset({"ipp", "cups"})
_IPP_PORTS = frozenset({631})
_DEFAULT_PORT = 631
# cups-info/cups-queue-info read the CUPS server version + print queues; the /printers/ web page
# lists configured printers. All read-only GETs — no job is submitted and no config is changed.


@dataclass
class IppStep:
    command: Command
    tool: str = ""


class IppModule(Module):
    name = "ipp"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in IPP_SERVICE_NAMES or s.port in _IPP_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[IppStep]:
        host = target.ip
        port_n = port or _DEFAULT_PORT
        return [
            IppStep(
                Command(
                    "ipp",
                    f"nmap -sV -p {port_n} --script cups-info,cups-queue-info {host}",
                    "CUPS server info + print-queue contents (read-only).",
                    "< 30s",
                    "ipp/nmap-info.txt",
                ),
                "ipp-nmap",
            ),
            IppStep(
                Command(
                    "ipp",
                    f"curl -s http://{host}:{port_n}/printers/",
                    "List configured printers via the CUPS web UI (read-only).",
                    "< 30s",
                    "ipp/printers.html",
                ),
                "ipp-curl",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        seen: set[tuple[str, str]] = set()
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for ipf in parse_ipp_tool(tool, text):
                if (ipf.kind, ipf.value) in seen:
                    continue
                seen.add((ipf.kind, ipf.value))
                findings.append(
                    Finding(
                        service="ipp",
                        title=f"{ipf.kind}: {ipf.value}",
                        detail=ipf.detail,
                        fields={"kind": ipf.kind, "value": ipf.value, "detail": ipf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        printers = [
            f.fields.get("value", "") for f in findings if f.fields.get("kind") == "printer"
        ]
        if printers:
            first = printers[0]
            return [
                f"{len(printers)} CUPS printer(s) exposed — read a printer's attributes/jobs "
                f"(`curl -s 'http://{{target}}:631/printers/{first}?op=get-printer-attributes'`)."
            ]
        return []
