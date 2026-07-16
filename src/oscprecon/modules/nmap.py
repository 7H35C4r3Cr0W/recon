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

# nmap's http-title NSE prints "Did not follow redirect to http://ignition.htb/" when a name-based
# vhost box bounces the IP to its hostname — that hostname is the whole recon on such boxes.
_REDIRECT_TITLE_RE = re.compile(
    r"follow(?:ed)?\s+redirect\s+to\s+https?://([A-Za-z0-9.-]+)", re.IGNORECASE
)
# a real vhost name: a letter + a dotted TLD, so a bare IP redirect is not mistaken for a vhost.
_VHOST_HOST_RE = re.compile(r"^(?=.*[A-Za-z])[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
# a version-shaped token: a dotted/dashed number (2.4.52, 8.2p1, 0.8.13). A product name that starts
# with a digit (3proxy, 3CX, 7-Zip) does NOT match, so it is not mistaken for its own version.
_VERSION_RE = re.compile(r"^v?\d+([.\-]\d+)+")


def redirect_vhosts(raw_outputs: dict[str, str]) -> list[str]:
    """Vhost hostnames nmap saw the target redirect to (http-title 'Did not follow redirect …')."""
    hosts: list[str] = []
    for text in raw_outputs.values():
        for match in _REDIRECT_TITLE_RE.finditer(text):
            host = match.group(1).rstrip("/").lower()
            if _VHOST_HOST_RE.match(host) and host not in hosts:
                hosts.append(host)
    return hosts


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
        return cmds

    def _udp_full_command(self, host: str) -> Command:
        return Command(
            "nmap",
            f"nmap -sU -p- {host}",
            "Full 65535-port UDP sweep — very slow; deferred to run after the versioned scan.",
            "slow",
            "nmap/udp-full.txt",
        )

    def deferred_commands(self, target: Target) -> list[Command]:
        # why: UDP -p- is hours-slow and low-yield, so it must never block the high-value versioned
        # TCP scan. The orchestrator runs these LAST (after -sV -sC) so the useful results land
        # first and the sweep can be cancelled once you have them. `full` includes it (what makes
        # `full` more than `default`); others only on the --udp-full opt-in (CLAUDE.md §8). `quick`
        # is TCP-only triage and never runs UDP, even with --udp-full.
        if self.scan_profile == "quick":
            return []
        if self.udp_full or self.scan_profile == "full":
            return [self._udp_full_command(target.ip)]
        return []

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
                # the -sV scan (it carries product/version) has the AUTHORITATIVE service name — let
                # it override the bare port-table guess (e.g. 8080 'http-proxy' -> 'http'); a scan
                # with no product only fills a blank/unknown name.
                if service.service and (service.product or existing.service in ("", "unknown")):
                    existing.service = service.service
                # the versioned/-sC scan carries the NSE script block (http-title, ssh-hostkey,
                # ssl-cert, smb-os-discovery…) the bare port-table sweep never has — fill it so the
                # report/tree surface those details (#7). Never let a blank re-scan wipe a filled.
                if service.nmap_scripts_output and not existing.nmap_scripts_output:
                    existing.nmap_scripts_output = service.nmap_scripts_output
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
        # Block parser: each port row owns the indented NSE script lines that follow it
        # (`| ssh-hostkey:`, `|_http-title: …`), captured into nmap_scripts_output so the report and
        # service tree can show the real enum detail — not just product/version (#7).
        services: list[DiscoveredService] = []
        current: DiscoveredService | None = None
        script_lines: list[str] = []

        def flush() -> None:
            if current is not None and script_lines:
                current.nmap_scripts_output = "\n".join(script_lines).rstrip()
            script_lines.clear()

        for raw in text.splitlines():
            service = parse_port_line(raw.strip())
            if service is not None:
                flush()
                services.append(service)
                current = service
                continue
            stripped = raw.strip()
            if current is not None and stripped.startswith("|"):
                script_lines.append(_clean_script_line(stripped))
            elif stripped and not stripped.startswith("|"):
                # a non-port, non-continuation line ("Service Info:", "Host script results:", "Nmap
                # done") ends the current port's NSE block — otherwise host-level scripts (smb-os-
                # discovery, clock-skew, smb-security-mode) get glued onto the last port row.
                flush()
                current = None
        flush()
        return services


def _clean_script_line(line: str) -> str:
    # strip nmap's NSE gutter marker ("| ", "|_", "|   ") but keep the nested indentation that
    # follows, so multi-line script output (hostkeys, cert SANs, smb-os-discovery) stays readable.
    body = line[1:]  # drop the leading '|'
    if body.startswith("_"):
        body = body[1:]
    if body.startswith(" "):
        body = body[1:]
    return body.rstrip()


def parse_port_line(line: str) -> DiscoveredService | None:
    """One nmap 'PORT STATE SERVICE VERSION' row → a DiscoveredService (None if not a port row).

    Reused by the pivot multi-host parser so both read nmap version columns identically."""
    match = _PORT_LINE.match(line.strip())
    if match is None:
        return None
    rest = match.group("rest") or ""
    product = ""
    version = ""
    # a leading "(" means nmap detected no product name, just parenthetical extrainfo
    # (rsync's "(protocol version 31)"); leave product/version empty rather than mangle it.
    if rest and not rest.startswith("("):
        # nmap's version column is "<product> [version] [extrainfo]" with a free-text,
        # often multi-word product ("Redis key-value store", "Samba smbd", "Linux telnetd").
        # Split on the first version-looking token (starts with a digit) so product and
        # version are clean and extrainfo noise is dropped; with no version token the whole
        # banner is the product. Splitting on the first word instead mangled both fields
        # (product "Redis", version "key-value store 5.0.7").
        tokens = rest.split()

        def _is_version(index: int, tok: str) -> bool:
            # a dotted/dashed number is a version anywhere (2.4.52, 8.2p1, 0.8.13); a BARE number is
            # a version only past position 0, so a product whose name starts with a digit (3proxy,
            # 3CX, 7-Zip) is not mistaken for its own version.
            if _VERSION_RE.match(tok):
                return True
            return index > 0 and tok[:1].isdigit()

        vi = next((i for i, tok in enumerate(tokens) if _is_version(i, tok)), None)
        if vi is None:
            product = " ".join(tokens)
        else:
            product = " ".join(tokens[:vi])
            version = tokens[vi]
    return DiscoveredService(
        port=int(match.group("port")),
        proto=Proto(match.group("proto")),
        service=match.group("service"),
        product=product,
        version=version,
        discovered_at=_now_iso(),
    )
