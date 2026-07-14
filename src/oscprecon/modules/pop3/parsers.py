from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class Pop3Finding:
    kind: str  # version | capabilities | stls | auth | domain | hostname | os-build
    value: str
    detail: str = ""
    module: str = "pop3"

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

_CAPS = re.compile(r"pop3-capabilities:\s*(?P<v>.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_SV_LINE = re.compile(r"^\d+/tcp\s+open\s+(?:ssl/)?pop3s?\s+(?P<v>.+?)\s*$", re.MULTILINE)
_DNS_COMPUTER = re.compile(r"DNS_Computer_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_NETBIOS_COMPUTER = re.compile(r"NetBIOS_Computer_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_DNS_DOMAIN = re.compile(r"DNS_Domain_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_NETBIOS_DOMAIN = re.compile(r"NetBIOS_Domain_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_PRODUCT_VERSION = re.compile(r"Product_Version:\s*(?P<v>[\d.]+)\s*$", re.MULTILINE)
# SASL mechanisms print as "SASL(PLAIN LOGIN)" (paren form) or "SASL PLAIN LOGIN" (space form).
_SASL_PAREN = re.compile(r"SASL\s*\((?P<m>[^)]+)\)", re.IGNORECASE)
_SASL_SPACE = re.compile(r"\bSASL\s+(?P<m>[A-Z0-9][A-Z0-9\- ]*?)(?=\s+[A-Z]+\b|$)")


def _first(rx: re.Pattern[str], text: str) -> str:
    match = rx.search(text)
    return match.group("v").strip() if match is not None else ""


def parse_pop3_info(text: str) -> list[Pop3Finding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[Pop3Finding] = []

    version = _first(_SV_LINE, text)
    if version:
        findings.append(Pop3Finding("version", version, "POP3 server (banner)"))

    caps = _first(_CAPS, text)
    if caps:
        findings.append(Pop3Finding("capabilities", caps, "POP3 CAPA list"))
        findings.append(
            Pop3Finding(
                "stls", "yes" if "STLS" in caps.upper() else "no", "STLS (STARTTLS) offered"
            )
        )
        sasl = _SASL_PAREN.search(caps) or _SASL_SPACE.search(caps)
        if sasl is not None and sasl.group("m").strip():
            mechs = sorted(set(sasl.group("m").split()))
            findings.append(Pop3Finding("auth", ", ".join(mechs), "SASL mechanisms"))

    hostname = _first(_DNS_COMPUTER, text) or _first(_NETBIOS_COMPUTER, text)
    if hostname:
        findings.append(Pop3Finding("hostname", hostname, "host (POP3 NTLM)"))
    domain = _first(_DNS_DOMAIN, text) or _first(_NETBIOS_DOMAIN, text)
    host_short = hostname.split(".")[0].lower()
    if domain and domain.upper() != "WORKGROUP" and domain.split(".")[0].lower() != host_short:
        findings.append(Pop3Finding("domain", domain, "AD domain (POP3 NTLM)"))
    os_build = _first(_PRODUCT_VERSION, text)
    if os_build:
        findings.append(Pop3Finding("os-build", os_build, "Windows build (POP3 NTLM)"))
    return findings


_PARSERS = {"pop3-info": parse_pop3_info}


def parse_pop3_tool(tool: str, text: str) -> list[Pop3Finding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
