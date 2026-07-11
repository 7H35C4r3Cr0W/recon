from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.ntp.parsers import NtpFinding, parse_ntp_tool, parse_ntpdate, parse_ntpq

__all__ = [
    "NTP_SERVICE_NAMES",
    "NtpFinding",
    "NtpModule",
    "NtpStep",
    "parse_ntp_tool",
    "parse_ntpdate",
    "parse_ntpq",
]

NTP_SERVICE_NAMES = frozenset({"ntp"})
_NTP_PORTS = frozenset({123})


@dataclass
class NtpStep:
    command: Command
    tool: str = ""  # parser key for the output, or "" when the output is not parsed


class NtpModule(Module):
    name = "ntp"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in NTP_SERVICE_NAMES or s.port in _NTP_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target) -> list[NtpStep]:
        host = target.ip
        return [
            NtpStep(
                Command(
                    "ntp",
                    f"ntpq -c readlist {host}",
                    "Read NTP system variables — ntpd version, OS, processor, stratum (read-only).",
                    "< 30s",
                    "ntp/ntpq-readlist.txt",
                ),
                "ntpq-readlist",
            ),
            NtpStep(
                Command(
                    "ntp",
                    f"ntpq -c sysinfo {host}",
                    "NTP system info — system peer, stratum, sync state (read-only).",
                    "< 30s",
                    "ntp/ntpq-sysinfo.txt",
                ),
                "ntpq-sysinfo",
            ),
            NtpStep(
                Command(
                    "ntp",
                    f"ntpdate -q {host}",
                    "Query the time without setting the local clock (-q) — stratum, offset.",
                    "< 30s",
                    "ntp/ntpdate.txt",
                ),
                "ntpdate",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for nf in parse_ntp_tool(tool, text):
                findings.append(
                    Finding(
                        service="ntp",
                        title=f"{nf.kind}: {nf.value}",
                        detail=nf.detail,
                        fields={"kind": nf.kind, "value": nf.value, "detail": nf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        info = [f.fields.get("value", "") for f in findings if f.fields.get("kind") == "info"]
        if info:
            out.append(
                f"NTP discloses host details ({info[0]}) — use them to fingerprint the OS/version; "
                "also check ntp-monlist (Tier-2 nmap) for a recent-clients list."
            )
        return out
