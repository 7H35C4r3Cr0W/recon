from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class WinrmFinding:
    kind: str  # host | domain | os | server | endpoint
    value: str
    detail: str = ""
    module: str = "winrm"

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
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

# netexec's WinRM banner: "... [*] Windows Server 2019 Build 17763 (name:HOST) (domain:corp.local)"
_NXC_OS = re.compile(r"\[\*\]\s*(?P<v>.+?)\s*\(name:", re.IGNORECASE)
_NXC_NAME = re.compile(r"\(name:\s*(?P<v>[^)]+)\)", re.IGNORECASE)
_NXC_DOMAIN = re.compile(r"\(domain:\s*(?P<v>[^)]+)\)", re.IGNORECASE)
_HTTP_STATUS = re.compile(r"^HTTP/\d(?:\.\d)?\s+(?P<v>\d{3})", re.MULTILINE)
_HTTP_SERVER = re.compile(r"^Server:\s*(?P<v>.+?)\s*$", re.MULTILINE | re.IGNORECASE)


def parse_winrm_nxc(text: str) -> list[WinrmFinding]:
    text = _ANSI.sub("", text)
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[WinrmFinding] = []
    name = _NXC_NAME.search(text)
    if name is not None:
        findings.append(WinrmFinding("host", name.group("v").strip(), "WinRM host (netexec)"))
    os_match = _NXC_OS.search(text)
    if os_match is not None:
        findings.append(WinrmFinding("os", os_match.group("v").strip(), "OS build (netexec)"))
    domain = _NXC_DOMAIN.search(text)
    if domain is not None:
        dom = domain.group("v").strip()
        host_short = name.group("v").split(".")[0].lower() if name is not None else ""
        if dom.upper() != "WORKGROUP" and dom.split(".")[0].lower() != host_short:
            findings.append(WinrmFinding("domain", dom, "AD domain (netexec WinRM)"))
    return findings


def parse_winrm_http(text: str) -> list[WinrmFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[WinrmFinding] = []
    status = _HTTP_STATUS.search(text)
    # a live WinRM listener answers a bare GET /wsman with 405 (Method Not Allowed) or 401
    if status is not None and status.group("v") in {"405", "401"}:
        findings.append(
            WinrmFinding("endpoint", f"live (HTTP {status.group('v')})", "WinRM /wsman responded")
        )
    server = _HTTP_SERVER.search(text)
    if server is not None and server.group("v").strip():
        findings.append(WinrmFinding("server", server.group("v").strip(), "Server header"))
    return findings


_PARSERS = {"winrm-nxc": parse_winrm_nxc, "winrm-http": parse_winrm_http}


def parse_winrm_tool(tool: str, text: str) -> list[WinrmFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
