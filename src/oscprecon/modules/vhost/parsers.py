from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


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
                status=int(result.get("status", 0) or 0),
                size=int(result.get("length", 0) or 0),
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


_DNSRECON = re.compile(r"\[[*+]\]\s+(?:A|AAAA|CNAME)\s+(?P<host>\S+)\s+(?P<ip>\S+)")


def parse_dnsrecon(text: str) -> list[VhostFinding]:
    findings: list[VhostFinding] = []
    for line in text.splitlines():
        match = _DNSRECON.search(line)
        if match is not None:
            findings.append(
                VhostFinding(vhost=match.group("host"), ip=match.group("ip"), note="dnsrecon brt")
            )
    return findings


def parse_vhost_tool(tool: str, text: str, domain: str = "") -> list[VhostFinding]:
    if tool == "ffuf":
        return parse_ffuf_vhost(text, domain)
    if tool in ("gobuster", "gobuster-vhost", "gobuster-dns"):
        return parse_gobuster_vhost(text)
    if tool == "dnsrecon":
        return parse_dnsrecon(text)
    return []
