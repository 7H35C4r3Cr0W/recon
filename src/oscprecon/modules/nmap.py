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

    def __init__(self, udp_full: bool = False, scan_profile: str = "default") -> None:
        self.udp_full = udp_full
        # why: unknown profiles fall back to the standard battery rather than raising — a stale
        # or hand-edited pref must never wedge the scan. config.Settings.normalized() validates
        # the persisted value; this is defence-in-depth for direct callers.
        self.scan_profile = scan_profile if scan_profile in ("quick", "full", "exam") else "default"

    def triggers(self, scan_results: ScanResults) -> bool:
        return True

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        host = target.ip
        if not ports:
            return self._discovery_battery(host)

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

    def _discovery_battery(self, host: str) -> list[Command]:
        # why: the profile only shapes the DISCOVERY phase; the versioned -sV -sC scan on found
        # ports is identical everywhere. exam-legal by construction — every line is `nmap` with
        # allow-listed flags, never `--script vuln` (opt-in via Nmap presets, not the auto battery).
        top1000 = Command(
            "nmap",
            f"nmap --top-ports 1000 {host}",
            "Fast sweep of the 1000 most common TCP ports.",
            "< 1 min",
            "nmap/tcp-top1000.txt",
        )
        top1000_fast = Command(
            "nmap",
            f"nmap --top-ports 1000 -T4 {host}",
            "Fast sweep of the 1000 most common TCP ports (speed-tuned).",
            "< 1 min",
            "nmap/tcp-top1000.txt",
        )
        udp_top100 = Command(
            "nmap",
            f"nmap -sU --top-ports 100 {host}",
            "UDP top-100 — SNMP/DNS/NetBIOS/TFTP hide here.",
            "1-5 min",
            "nmap/udp-top100.txt",
        )
        udp_full = Command(
            "nmap",
            f"nmap -sU -p- {host}",
            "Full UDP sweep — very slow, opt-in only.",
            "slow",
            "nmap/udp-full.txt",
        )
        if self.scan_profile == "quick":
            return [top1000_fast]  # fast triage: no full -p-, no UDP
        if self.scan_profile == "exam":
            cmds = [
                top1000_fast,
                Command(
                    "nmap",
                    f"nmap -p- --min-rate 1000 -T4 {host}",
                    "Full 65535-port TCP sweep, rate-boosted to finish fast under exam time. "
                    "No --script vuln.",
                    "2-8 min",
                    "nmap/tcp-full.txt",
                ),
                udp_top100,
            ]
        else:  # default / full
            cmds = [
                top1000,
                Command(
                    "nmap",
                    f"nmap -p- {host}",
                    "Full 65535-port TCP sweep — catches services on odd ports.",
                    "5-15 min",
                    "nmap/tcp-full.txt",
                ),
                udp_top100,
            ]
        # `full` always adds the slow UDP sweep; others only on the explicit udp_full opt-in.
        if self.udp_full or self.scan_profile == "full":
            cmds.append(udp_full)
        return cmds

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
                # nmap's version column is "<product> [version] [extrainfo]" with a free-text,
                # often multi-word product ("Redis key-value store", "Samba smbd", "Linux telnetd").
                # Split on the first version-looking token (starts with a digit) so product and
                # version are clean and extrainfo noise is dropped; with no version token the whole
                # banner is the product. Splitting on the first word instead mangled both fields
                # (product "Redis", version "key-value store 5.0.7").
                tokens = rest.split()
                vi = next((i for i, tok in enumerate(tokens) if tok[:1].isdigit()), None)
                if vi is None:
                    product = " ".join(tokens)
                else:
                    product = " ".join(tokens[:vi])
                    version = tokens[vi]
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
