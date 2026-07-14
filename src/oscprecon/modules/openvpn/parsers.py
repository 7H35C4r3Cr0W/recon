from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class OpenvpnFinding:
    kind: str  # service | version | transport
    value: str
    detail: str = ""
    module: str = "openvpn"

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
# nmap confirms the service on the port line: "1194/udp open openvpn" (an optional version follows).
_OPENVPN = re.compile(
    r"^\d+/(?P<proto>tcp|udp)\s+open(?:\|filtered)?\s+openvpn\s*(?P<v>.*?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)


def parse_openvpn_info(text: str) -> list[OpenvpnFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    match = _OPENVPN.search(text)
    if match is None:
        return []
    findings = [OpenvpnFinding("service", "openvpn", "OpenVPN service confirmed (nmap)")]
    findings.append(OpenvpnFinding("transport", match.group("proto").lower(), "OpenVPN transport"))
    version = match.group("v").strip()
    if version:
        findings.append(OpenvpnFinding("version", version, "OpenVPN version (banner)"))
    return findings


_PARSERS = {"openvpn-info": parse_openvpn_info}


def parse_openvpn_tool(tool: str, text: str) -> list[OpenvpnFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
