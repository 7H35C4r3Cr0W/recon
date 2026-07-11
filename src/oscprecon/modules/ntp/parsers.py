from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class NtpFinding:
    kind: str  # info | stratum | peer
    value: str
    detail: str = ""
    module: str = "ntp"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


# ntpq -c readlist / rv prints `key="value"` pairs — version/system/processor fingerprint the host.
_INFO_KEYS = (("version", "ntpd version"), ("system", "OS"), ("processor", "processor"))
# stratum appears as `stratum=3` (readlist) or `stratum:   3` (sysinfo).
_STRATUM = re.compile(r"stratum[=:\s]+(?P<s>\d+)", re.IGNORECASE)
# ntpdate -q line: `server 10.0.0.1, stratum 3, offset ...`. The server may be IPv4, IPv6, or a
# hostname (Target accepts IPv6), so capture non-greedily up to `, stratum`, not a dotted quad.
_NTPDATE = re.compile(r"server\s+(?P<ip>\S+?),\s*stratum\s+(?P<s>\d+)", re.IGNORECASE)


def parse_ntpq(text: str) -> list[NtpFinding]:
    findings: list[NtpFinding] = []
    for key, label in _INFO_KEYS:
        match = re.search(rf'{key}="(?P<v>[^"]*)"', text)
        if match is not None and match.group("v").strip():
            findings.append(NtpFinding("info", f"{label}: {match.group('v').strip()}"))
    stratum = _STRATUM.search(text)
    if stratum is not None:
        findings.append(NtpFinding("stratum", stratum.group("s")))
    return findings


def parse_ntpdate(text: str) -> list[NtpFinding]:
    findings: list[NtpFinding] = []
    match = _NTPDATE.search(text)
    if match is not None:
        findings.append(NtpFinding("stratum", match.group("s"), f"server {match.group('ip')}"))
    return findings


_PARSERS = {
    "ntpq-readlist": parse_ntpq,
    "ntpq-sysinfo": parse_ntpq,
    "ntpdate": parse_ntpdate,
}


def parse_ntp_tool(tool: str, text: str) -> list[NtpFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
