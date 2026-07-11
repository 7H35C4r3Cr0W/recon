from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_RECORD_TYPES = frozenset(
    {"A", "AAAA", "NS", "MX", "SOA", "TXT", "CNAME", "PTR", "SRV", "HINFO", "CAA"}
)
_AXFR_FAIL = ("transfer failed", "communications error", "timed out", "couldn't get address")


@dataclass
class DnsFinding:
    kind: str  # version | record | zone-transfer | recursion | note
    value: str
    detail: str = ""
    module: str = "dns"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


def parse_dig_version(text: str) -> list[DnsFinding]:
    for raw in text.splitlines():
        line = raw.strip().strip('"')
        if not line or line.startswith(";"):
            continue
        return [DnsFinding("version", line, "version.bind")]
    return []


# a dig AXFR record row: `name  TTL  IN  TYPE  data` (class IN is sometimes absent).
_DIG_RECORD = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+\.?)\s+\d+\s+(?:IN\s+)?(?P<type>[A-Z]+)\s+(?P<data>\S.*?)\s*$"
)


def _record(name: str, rtype: str, data: str) -> DnsFinding:
    # why: findings.json dedups on (module, kind, value); a bare hostname would collapse every
    # record type for that host into one, dropping zone data — so the value is the full row.
    return DnsFinding("record", f"{name} {rtype} {data}".strip(), rtype)


def parse_dig_axfr(text: str) -> list[DnsFinding]:
    findings: list[DnsFinding] = []
    records: list[tuple[str, str, str]] = []
    lower = text.lower()
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith(";"):
            continue
        match = _DIG_RECORD.match(line)
        if match is None or match.group("type") not in _RECORD_TYPES:
            continue
        key = (match.group("name"), match.group("type"), match.group("data").strip())
        if key not in records:
            records.append(key)
    for name, rtype, data in records:
        findings.append(_record(name, rtype, data))
    if records:
        findings.append(
            DnsFinding("zone-transfer", "allowed", f"AXFR succeeded — {len(records)} records")
        )
    elif any(marker in lower for marker in _AXFR_FAIL):
        findings.append(DnsFinding("zone-transfer", "denied", "AXFR refused or failed"))
    return findings


# dnsrecon rows: `[*]      A example.com 10.10.10.5`.
_DNSRECON_RECORD = re.compile(r"^\[\*\]\s+(?P<type>[A-Z]+)\s+(?P<name>\S+)\s+(?P<data>\S.*?)\s*$")


def parse_dnsrecon(text: str) -> list[DnsFinding]:
    findings: list[DnsFinding] = []
    records: list[tuple[str, str, str]] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        match = _DNSRECON_RECORD.match(line)
        if match is not None and match.group("type") in _RECORD_TYPES:
            key = (match.group("name"), match.group("type"), match.group("data").strip())
            if key not in records:
                records.append(key)
    for name, rtype, data in records:
        findings.append(_record(name, rtype, data))
    if "zone transfer was successful" in text.lower():
        findings.append(DnsFinding("zone-transfer", "allowed", "dnsrecon AXFR succeeded"))
    return findings


_NMAP_VER = re.compile(r"^\d+/(?:tcp|udp)\s+open\s+domain\s+(?P<ver>\S.*)$", re.MULTILINE)
_NSID = re.compile(r"bind\.version:\s*(?P<ver>\S.*?)\s*$", re.MULTILINE)


def parse_nmap_dns(text: str) -> list[DnsFinding]:
    findings: list[DnsFinding] = []
    nsid = _NSID.search(text)
    if nsid is not None:
        findings.append(DnsFinding("version", nsid.group("ver").strip(), "dns-nsid"))
    else:
        version = _NMAP_VER.search(text)
        if version is not None:
            findings.append(DnsFinding("version", version.group("ver").strip(), "nmap -sV"))
    lower = text.lower()
    if "recursion appears to be enabled" in lower:
        findings.append(DnsFinding("recursion", "enabled", "open resolver"))
    elif "recursion appears to be disabled" in lower:
        findings.append(DnsFinding("recursion", "disabled", ""))
    return findings


_PARSERS = {
    "dig-version": parse_dig_version,
    "dig-axfr": parse_dig_axfr,
    "dnsrecon": parse_dnsrecon,
    "nmap-dns": parse_nmap_dns,
}


def parse_dns_tool(tool: str, text: str) -> list[DnsFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
