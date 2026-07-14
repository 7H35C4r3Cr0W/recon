from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class TelnetFinding:
    kind: str  # version | encryption | domain | hostname | os-build
    value: str
    detail: str = ""
    module: str = "telnet"

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

_ENC_YES = re.compile(r"supports encryption", re.IGNORECASE)
_ENC_NO = re.compile(r"does not support encryption", re.IGNORECASE)
_SV_LINE = re.compile(r"^\d+/tcp\s+open\s+telnet\??\s+(?P<v>.+?)\s*$", re.MULTILINE)
_DNS_COMPUTER = re.compile(r"DNS_Computer_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_NETBIOS_COMPUTER = re.compile(r"NetBIOS_Computer_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_DNS_DOMAIN = re.compile(r"DNS_Domain_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_NETBIOS_DOMAIN = re.compile(r"NetBIOS_Domain_Name:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_PRODUCT_VERSION = re.compile(r"Product_Version:\s*(?P<v>[\d.]+)\s*$", re.MULTILINE)


def _first(rx: re.Pattern[str], text: str) -> str:
    match = rx.search(text)
    return match.group("v").strip() if match is not None else ""


def parse_telnet_info(text: str) -> list[TelnetFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[TelnetFinding] = []

    version = _first(_SV_LINE, text)
    if version:
        findings.append(TelnetFinding("version", version, "telnet server (banner)"))

    if _ENC_NO.search(text):
        findings.append(TelnetFinding("encryption", "not-supported", "no transport encryption"))
    elif _ENC_YES.search(text):
        findings.append(TelnetFinding("encryption", "supported", "transport encryption offered"))

    hostname = _first(_DNS_COMPUTER, text) or _first(_NETBIOS_COMPUTER, text)
    if hostname:
        findings.append(TelnetFinding("hostname", hostname, "host (telnet NTLM)"))
    domain = _first(_DNS_DOMAIN, text) or _first(_NETBIOS_DOMAIN, text)
    host_short = hostname.split(".")[0].lower()
    if domain and domain.upper() != "WORKGROUP" and domain.split(".")[0].lower() != host_short:
        findings.append(TelnetFinding("domain", domain, "AD domain (telnet NTLM)"))
    os_build = _first(_PRODUCT_VERSION, text)
    if os_build:
        findings.append(TelnetFinding("os-build", os_build, "Windows build (telnet NTLM)"))
    return findings


_PARSERS = {"telnet-info": parse_telnet_info}


def parse_telnet_tool(tool: str, text: str) -> list[TelnetFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
