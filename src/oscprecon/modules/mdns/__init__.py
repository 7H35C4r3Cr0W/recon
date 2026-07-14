from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.mdns.parsers import (
    MdnsFinding,
    parse_mdns_info,
    parse_mdns_tool,
)

__all__ = [
    "MDNS_SERVICE_NAMES",
    "MdnsFinding",
    "MdnsModule",
    "MdnsStep",
    "parse_mdns_info",
    "parse_mdns_tool",
]

MDNS_SERVICE_NAMES = frozenset({"mdns", "zeroconf"})
_MDNS_PORTS = frozenset({5353})
_DEFAULT_PORT = 5353
# dns-service-discovery asks the mDNS responder to advertise its services; it leaks internal service
# names, ports and host addresses read-only. mDNS is UDP, so -sU is required.
_INFO_SCRIPTS = "dns-service-discovery"


@dataclass
class MdnsStep:
    command: Command
    tool: str = ""


class MdnsModule(Module):
    name = "mdns"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in MDNS_SERVICE_NAMES or s.port in _MDNS_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[MdnsStep]:
        shell_line = f"nmap -sU -p {port or _DEFAULT_PORT} --script {_INFO_SCRIPTS} {target.ip}"
        return [
            MdnsStep(
                Command(
                    "mdns",
                    shell_line,
                    "dns-service-discovery — advertised services, ports and host addresses "
                    "(read-only; mDNS is UDP so it may need a retry).",
                    "< 1 min",
                    "mdns/nmap-info.txt",
                ),
                "mdns-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        seen: set[tuple[str, str]] = set()
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for mf in parse_mdns_tool(tool, text):
                if (mf.kind, mf.value) in seen:
                    continue
                seen.add((mf.kind, mf.value))
                findings.append(
                    Finding(
                        service="mdns",
                        title=f"{mf.kind}: {mf.value}",
                        detail=mf.detail,
                        fields={"kind": mf.kind, "value": mf.value, "detail": mf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        services = [
            f.fields.get("value", "") for f in findings if f.fields.get("kind") == "service"
        ]
        if services:
            return [
                f"mDNS advertised {len(services)} service(s) — enumerate the advertised ports "
                "directly (they are often not in the top-1000 TCP scan)."
            ]
        return []
