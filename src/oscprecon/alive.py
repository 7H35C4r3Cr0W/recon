from __future__ import annotations

import re
from dataclasses import dataclass, field

from oscprecon.models import is_cidr_range, validate_host_or_range

# Pre-flight "is it alive?" check — a quick nmap host-discovery sweep (`-sn`, no port scan) run
# BEFORE the full recon so you know the target answered before you commit to a long scan. Exam-legal
# host discovery: plain nmap, no brute/spoof. Windows boxes filter ICMP, so we also TCP-ping common
# ports (SYN + ACK), otherwise a live-but-ICMP-filtered box reads as down.

_PING_TCP_SYN = "21,22,80,135,139,443,445,3389,8080"
_PING_TCP_ACK = "80,443,3389"

_REPORT_RE = re.compile(r"^Nmap scan report for\s+(?P<who>.+?)\s*$")
_IP_IN_PARENS = re.compile(r"\(([0-9A-Fa-f:.]+)\)\s*$")
_UP_RE = re.compile(r"^Host is up(?:\s+\(([^)]*)\))?", re.IGNORECASE)


def build_alive_command(target: str) -> str:
    # ICMP echo/timestamp/netmask + TCP SYN/ACK to common ports = a live host answers at least one.
    # -n skips slow reverse DNS; a per-host timeout keeps a dead single host from hanging the check.
    # A CIDR range is swept the same way (no per-host timeout so a full /24 completes).
    validated = validate_host_or_range(target)
    host_timeout = "" if is_cidr_range(validated) else "--host-timeout 15s "
    return (
        f"nmap -sn -n -PE -PP -PM -PS{_PING_TCP_SYN} -PA{_PING_TCP_ACK} {host_timeout}{validated}"
    )


@dataclass
class AliveResult:
    hosts: list[str] = field(default_factory=list)  # up hosts, in nmap-report order
    latency: str = ""  # first up host's latency string ("0.021s latency"), if reported

    @property
    def up(self) -> bool:
        return bool(self.hosts)

    @property
    def count(self) -> int:
        return len(self.hosts)


def parse_alive(text: str) -> AliveResult:
    """Up hosts from `nmap -sn` output. A down host prints no report line (or 'Host seems down'), so
    an empty result == nothing answered. Robust to a range sweep (one report block per up host)."""
    result = AliveResult()
    pending: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        report = _REPORT_RE.match(line)
        if report is not None:
            who = report.group("who")
            in_parens = _IP_IN_PARENS.search(who)
            tokens = who.split()
            pending = in_parens.group(1) if in_parens else (tokens[0] if tokens else who)
            continue
        up = _UP_RE.match(line)
        if up is not None and pending is not None:
            result.hosts.append(pending)
            if not result.latency and up.group(1):
                result.latency = up.group(1)
            pending = None
    return result
