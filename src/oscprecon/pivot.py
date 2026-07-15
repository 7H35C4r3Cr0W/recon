from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime

from oscprecon.models import DiscoveredHost, subnet_of
from oscprecon.modules.nmap import parse_port_line

# Parse a MULTI-host nmap run — the output of scanning a /24 (or a host list) from a foothold once
# ligolo-ng routes the internal network — into DiscoveredHosts for the pivot topology. Nabu never
# runs the pivot scan itself (the user owns the tunnel); it ingests the output and organises it.
#
# Works for both `nmap -sn <cidr>` (host discovery — hosts with no services) and a versioned scan
# (`nmap -sV`/`-sC` — hosts with services). It reads the plain nmap text format:
#
#   Nmap scan report for 10.10.5.23
#   Host is up (0.0011s latency).
#   PORT     STATE SERVICE       VERSION
#   445/tcp  open  microsoft-ds  Windows Server 2019
#   Nmap scan report for dc02.corp.local (10.10.5.40)
#   ...

_REPORT_RE = re.compile(r"^Nmap scan report for\s+(?P<who>.+?)\s*$")
_IP_IN_PARENS = re.compile(r"^(?P<name>.+?)\s+\((?P<ip>[0-9A-Fa-f:.]+)\)$")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _split_report_target(who: str) -> tuple[str, str]:
    # "dc02.corp.local (10.10.5.40)" -> ("10.10.5.40", "dc02.corp.local"); a bare "10.10.5.23" ->
    # ("10.10.5.23", ""). Group by the IP so the /24 grouping works; keep the hostname as a label.
    match = _IP_IN_PARENS.match(who)
    if match is None:
        return who, ""
    ip = match.group("ip")
    name = match.group("name").strip()
    return ip, ("" if name == ip else name)


def _make_host(ip: str, hostname: str, pivot_source: str) -> DiscoveredHost | None:
    # DiscoveredHost validates ip + hostname (they reach command lines) — a bad token returns None
    # instead of raising, so one malformed report line never aborts the whole import.
    try:
        return DiscoveredHost(
            ip=ip,
            hostname=hostname,
            pivot_source=pivot_source,
            subnet=subnet_of(ip),
            discovered_at=_now_iso(),
        )
    except ValueError:
        return None


def parse_nmap_hosts(text: str, pivot_source: str = "") -> list[DiscoveredHost]:
    """Every up host in a multi-host nmap output, with its open-port services. Malformed host lines
    are skipped (never raised) so pasted output with odd banners still imports cleanly."""
    hosts: list[DiscoveredHost] = []
    current: DiscoveredHost | None = None
    for raw in text.splitlines():
        line = raw.strip()
        report = _REPORT_RE.match(line)
        if report is not None:
            current = None
            ip, hostname = _split_report_target(report.group("who"))
            current = _make_host(ip, hostname, pivot_source)
            if current is None and hostname:
                # a bad hostname (odd chars) must not lose a valid IP — retry with the IP only
                current = _make_host(ip, "", pivot_source)
            if current is None:
                continue  # neither the ip nor the token is a usable host — skip its whole block
            hosts.append(current)
            continue
        if current is None:
            continue
        lowered = line.lower()
        if lowered.startswith("host seems down") or lowered.startswith("host is down"):
            if hosts and hosts[-1] is current:  # nmap declared the host we just added as down
                hosts.pop()
            current = None
            continue
        service = parse_port_line(line)
        if service is not None:
            current.services.append(service)
    return hosts


def parse_host_lines(text: str, pivot_source: str = "") -> list[DiscoveredHost]:
    """A plain list of IPs (one per line, first token) → hosts. IP-validated, so prose lines like
    'Host is up' can never become a bogus host. For pasting a bare ligolo host-discovery list."""
    hosts: list[DiscoveredHost] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        parts = raw.strip().split()
        if not parts:
            continue
        token = parts[0]
        if token in seen:
            continue
        try:
            ipaddress.ip_address(token)  # ONLY real IPs — not hostnames, not prose
        except ValueError:
            continue
        seen.add(token)
        hosts.append(
            DiscoveredHost(
                ip=token,
                pivot_source=pivot_source,
                subnet=subnet_of(token),
                discovered_at=_now_iso(),
            )
        )
    return hosts


def parse_pivot_input(text: str, pivot_source: str = "") -> list[DiscoveredHost]:
    """Ingest pasted pivot recon: full nmap output when it looks like one, else a bare IP list."""
    if "Nmap scan report for" in text:
        return parse_nmap_hosts(text, pivot_source)
    return parse_host_lines(text, pivot_source)
