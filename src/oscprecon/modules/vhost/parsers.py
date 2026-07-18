from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from oscprecon.modules.http.parsers import is_vhost_host


@dataclass
class VhostFinding:
    vhost: str
    status: int = 0
    size: int = 0
    ip: str = ""
    note: str = ""
    module: str = "vhost"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "vhost": self.vhost,
            "status": self.status,
            "size": self.size,
            "ip": self.ip,
            "note": self.note,
            "discovered_at": discovered_at,
        }


def _to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def parse_ffuf_vhost(text: str, domain: str) -> list[VhostFinding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    results = data.get("results", [])
    findings: list[VhostFinding] = []
    if not isinstance(results, list):
        return findings
    for result in results:
        if not isinstance(result, dict):
            continue
        payload = result.get("input", {})
        fuzz = str(payload.get("FUZZ", "")) if isinstance(payload, dict) else ""
        if not fuzz:
            continue
        vhost = f"{fuzz}.{domain}" if domain else fuzz
        findings.append(
            VhostFinding(
                vhost=vhost,
                status=_to_int(result.get("status", 0)),
                size=_to_int(result.get("length", 0)),
            )
        )
    return findings


_GOBUSTER_VHOST = re.compile(
    r"Found:\s+(?P<vhost>\S+).*?Status:\s*(?P<status>\d+).*?\[Size:\s*(?P<size>\d+)\]"
)


def parse_gobuster_vhost(text: str) -> list[VhostFinding]:
    findings: list[VhostFinding] = []
    for line in text.splitlines():
        match = _GOBUSTER_VHOST.search(line)
        if match is not None:
            findings.append(
                VhostFinding(
                    vhost=match.group("vhost"),
                    status=int(match.group("status")),
                    size=int(match.group("size")),
                )
            )
    return findings


# gobuster dns result line: "www.example.com" or "Found: www.example.com" or
# "www.example.com 10.0.0.1,10.0.0.2" (host, optional comma-separated IPs).
_GOBUSTER_DNS = re.compile(
    r"^(?:Found:\s+)?(?P<host>[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)(?:\s+(?P<ip>[0-9a-fA-F.:,]+))?\s*$"
)


def parse_gobuster_dns(text: str) -> list[VhostFinding]:
    findings: list[VhostFinding] = []
    for line in text.splitlines():
        match = _GOBUSTER_DNS.match(line.strip())
        if match is not None:
            host = match.group("host")
            # the dotted-token pattern also matches version strings ('2.4.5') and bare hex — require
            # a real hostname shape (a letter + a dotted alpha TLD) before recording it as a vhost.
            if not is_vhost_host(host):
                continue
            ip = (match.group("ip") or "").split(",")[0]
            findings.append(VhostFinding(vhost=host, ip=ip, note="gobuster dns"))
    return findings


# dnsrecon: pre-1.x "[+] A host ip"; 1.6.0 "<timestamp> INFO \t A host ip".
_DNSRECON = re.compile(r"(?:\[[*+]\]|INFO)\s+(?:A|AAAA|CNAME)\s+(?P<host>\S+)\s+(?P<ip>\S+)")


def parse_dnsrecon(text: str) -> list[VhostFinding]:
    findings: list[VhostFinding] = []
    for line in text.splitlines():
        match = _DNSRECON.search(line)
        if match is not None:
            findings.append(
                VhostFinding(vhost=match.group("host"), ip=match.group("ip"), note="dnsrecon brt")
            )
    return findings


# dnsenum record row — the host/NS/MX, brute-force and zone-transfer sections all share this shape:
# "admin.example.htb.   5   IN   A   10.10.10.10" (hostname + optional trailing dot, TTL, IN, type).
_DNSENUM = re.compile(
    r"^(?P<host>[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)\.?\s+\d+\s+IN\s+"
    r"(?P<type>A|AAAA|CNAME)\s+(?P<data>\S+)\s*$"
)


def parse_dnsenum(text: str) -> list[VhostFinding]:
    findings: list[VhostFinding] = []
    seen: set[str] = set()
    for line in text.splitlines():
        match = _DNSENUM.match(line.strip())
        if match is None:
            continue
        host = match.group("host").rstrip(".")
        # the dotted pattern also matches a stray version-ish token — require a real hostname shape,
        # and dedup so the same host appearing in both the record + brute sections lists once.
        if not is_vhost_host(host) or host in seen:
            continue
        seen.add(host)
        # A/AAAA data is the IP; a CNAME's data is the canonical hostname, not an address — leave ip
        # empty there (the discovered subdomain itself is the finding).
        ip = match.group("data").rstrip(".") if match.group("type") in ("A", "AAAA") else ""
        findings.append(VhostFinding(vhost=host, ip=ip, note="dnsenum"))
    return findings


# wfuzz default line: '000023:   200   7 L   11 W   162 Ch   "admin"' (older uses 'C=200').
_WFUZZ = re.compile(
    r'^\d+:\s+(?:C=)?(?P<status>\d{3})\s+\d+ L\s+\d+ W\s+(?P<size>\d+) Ch\s+"(?P<payload>[^"]*)"'
)


def parse_wfuzz(text: str, domain: str) -> list[VhostFinding]:
    findings: list[VhostFinding] = []
    for line in text.splitlines():
        match = _WFUZZ.match(line.strip())
        if match is not None:
            payload = match.group("payload")
            vhost = f"{payload}.{domain}" if domain else payload
            findings.append(
                VhostFinding(
                    vhost=vhost, status=int(match.group("status")), size=int(match.group("size"))
                )
            )
    return findings


def parse_vhost_tool(tool: str, text: str, domain: str = "") -> list[VhostFinding]:
    if tool == "ffuf":
        return parse_ffuf_vhost(text, domain)
    if tool in ("gobuster", "gobuster-vhost"):
        return parse_gobuster_vhost(text)
    if tool == "gobuster-dns":
        return parse_gobuster_dns(text)
    if tool == "dnsrecon":
        return parse_dnsrecon(text)
    if tool == "dnsenum":
        return parse_dnsenum(text)
    if tool == "wfuzz":
        return parse_wfuzz(text, domain)
    return []
