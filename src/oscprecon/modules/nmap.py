from __future__ import annotations

import re
from datetime import UTC, datetime

from oscprecon.models import (
    Command,
    DiscoveredService,
    Finding,
    Port,
    Proto,
    ScanResults,
    Target,
)
from oscprecon.modules.base import Module

_PORT_LINE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+"
    r"(?P<state>open(?:\|filtered)?)\s+"
    r"(?P<service>\S+)(?:\s+(?P<rest>.*\S))?\s*$"
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class NmapModule(Module):
    name = "nmap"

    def __init__(self, udp_full: bool = False) -> None:
        self.udp_full = udp_full

    def triggers(self, scan_results: ScanResults) -> bool:
        return True

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        host = target.ip
        if not ports:
            cmds = [
                Command(
                    "nmap",
                    f"nmap --top-ports 1000 {host}",
                    "Fast sweep of the 1000 most common TCP ports.",
                    "< 1 min",
                    "nmap/tcp-top1000.txt",
                ),
                Command(
                    "nmap",
                    f"nmap -p- {host}",
                    "Full 65535-port TCP sweep — catches services on odd ports.",
                    "5-15 min",
                    "nmap/tcp-full.txt",
                ),
                Command(
                    "nmap",
                    f"nmap -sU --top-ports 100 {host}",
                    "UDP top-100 — SNMP/DNS/NetBIOS/TFTP hide here.",
                    "1-5 min",
                    "nmap/udp-top100.txt",
                ),
            ]
            if self.udp_full:
                cmds.append(
                    Command(
                        "nmap",
                        f"nmap -sU -p- {host}",
                        "Full UDP sweep — very slow, opt-in only.",
                        "slow",
                        "nmap/udp-full.txt",
                    )
                )
            return cmds

        tcp_ports = sorted({p.number for p in ports if p.proto == Proto.TCP})
        if not tcp_ports:
            return []
        joined = ",".join(str(p) for p in tcp_ports)
        return [
            Command(
                "nmap",
                f"nmap -sV -sC -p {joined} {host}",
                "Version + default-script scan on the discovered open TCP ports.",
                "1-5 min",
                "nmap/tcp-versioned.txt",
            )
        ]

    def discovered_services(self, raw_outputs: dict[str, str]) -> list[DiscoveredService]:
        merged: dict[tuple[int, Proto], DiscoveredService] = {}
        for text in raw_outputs.values():
            for service in self._parse_text(text):
                key = (service.port, service.proto)
                existing = merged.get(key)
                if existing is None:
                    merged[key] = service
                    continue
                if service.product and not existing.product:
                    existing.product = service.product
                if service.version and not existing.version:
                    existing.version = service.version
                if service.service and existing.service in ("", "unknown"):
                    existing.service = service.service
        return sorted(merged.values(), key=lambda s: (s.proto.value, s.port))

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for service in self.discovered_services(raw_outputs):
            title = f"{service.port}/{service.proto.value} {service.service}".strip()
            detail = " ".join(part for part in (service.product, service.version) if part)
            findings.append(
                Finding(
                    service=service.service or "unknown",
                    title=title,
                    detail=detail,
                    port=service.port,
                    proto=service.proto,
                )
            )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        return []

    def _parse_text(self, text: str) -> list[DiscoveredService]:
        services: list[DiscoveredService] = []
        for line in text.splitlines():
            match = _PORT_LINE.match(line.strip())
            if match is None:
                continue
            rest = match.group("rest") or ""
            product = ""
            version = ""
            if rest:
                parts = rest.split(None, 1)
                product = parts[0]
                version = parts[1].strip() if len(parts) > 1 else ""
            services.append(
                DiscoveredService(
                    port=int(match.group("port")),
                    proto=Proto(match.group("proto")),
                    service=match.group("service"),
                    product=product,
                    version=version,
                    discovered_at=_now_iso(),
                )
            )
        return services
