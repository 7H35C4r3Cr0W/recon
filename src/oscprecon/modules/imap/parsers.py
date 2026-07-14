from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class ImapFinding:
    kind: str  # version | capabilities | starttls | auth | domain | hostname | os-build
    value: str
    detail: str = ""
    module: str = "imap"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


# A missing/blocked wrapped tool writes a sentinel line to the output file (shell.run) — skip those.
_SENTINEL = ("[missing]", "[blocked]")

_CAPS = re.compile(r"imap-capabilities:\s*(?P<v>.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_SV_LINE = re.compile(r"^\d+/tcp\s+open\s+(?:ssl/)?imaps?\s+(?P<v>.+?)\s*$", re.MULTILINE)
_DNS_COMPUTER = re.compile(r"DNS_Computer_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_NETBIOS_COMPUTER = re.compile(r"NetBIOS_Computer_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_DNS_DOMAIN = re.compile(r"DNS_Domain_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_NETBIOS_DOMAIN = re.compile(r"NetBIOS_Domain_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_PRODUCT_VERSION = re.compile(r"Product_Version:\s*(?P<v>[\d.]+)\s*$", re.MULTILINE)


def _first(rx: re.Pattern[str], text: str) -> str:
    match = rx.search(text)
    return match.group("v").strip() if match is not None else ""


def parse_imap_info(text: str) -> list[ImapFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[ImapFinding] = []

    version = _first(_SV_LINE, text)
    if version:
        findings.append(ImapFinding("version", version, "IMAP server (banner)"))

    caps = _first(_CAPS, text)
    if caps:
        findings.append(ImapFinding("capabilities", caps, "IMAP CAPABILITY list"))
        findings.append(
            ImapFinding(
                "starttls", "yes" if "STARTTLS" in caps.upper() else "no", "STARTTLS offered"
            )
        )
        mechs = sorted(set(re.findall(r"AUTH=(?P<m>[A-Za-z0-9\-]+)", caps, re.IGNORECASE)))
        if mechs:
            findings.append(ImapFinding("auth", ", ".join(mechs), "offered auth mechanisms"))

    hostname = _first(_DNS_COMPUTER, text) or _first(_NETBIOS_COMPUTER, text)
    if hostname:
        findings.append(ImapFinding("hostname", hostname, "host (IMAP NTLM)"))
    domain = _first(_DNS_DOMAIN, text) or _first(_NETBIOS_DOMAIN, text)
    host_short = hostname.split(".")[0].lower()
    if domain and domain.upper() != "WORKGROUP" and domain.split(".")[0].lower() != host_short:
        findings.append(ImapFinding("domain", domain, "AD domain (IMAP NTLM)"))
    os_build = _first(_PRODUCT_VERSION, text)
    if os_build:
        findings.append(ImapFinding("os-build", os_build, "Windows build (IMAP NTLM)"))
    return findings


_PARSERS = {"imap-info": parse_imap_info}


def parse_imap_tool(tool: str, text: str) -> list[ImapFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
