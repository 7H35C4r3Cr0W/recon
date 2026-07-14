from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class VncFinding:
    kind: str  # version | security | access | desktop
    value: str
    detail: str = ""
    module: str = "vnc"

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

_VERSION = re.compile(r"(?:Protocol version|VNC version):\s*(?P<v>[\d.]+)", re.IGNORECASE)
_DESKTOP = re.compile(r"Desktop name:\s*(?P<v>.+?)\s*$", re.MULTILINE | re.IGNORECASE)
# offered RFB security types, each printed as "<name> (<code>)"; the recognised names below keep a
# stray "(2)" elsewhere in the output from being mistaken for a security type.
_SEC_NAMES = (
    "None",
    "VNC Authentication",
    "Tight",
    "TLS",
    "VeNCrypt",
    "RA2",
    "RA2ne",
    "Ultra",
    "MSLogon",
    "ARD",
)
_SEC_TYPE = re.compile(
    r"\b(?P<name>" + "|".join(re.escape(n) for n in _SEC_NAMES) + r")\s*\((?P<code>\d+)\)"
)


def parse_vnc_info(text: str) -> list[VncFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[VncFinding] = []

    version = _VERSION.search(text)
    if version is not None:
        findings.append(VncFinding("version", version.group("v").strip(), "RFB protocol version"))

    seen: set[str] = set()
    open_display = False
    for match in _SEC_TYPE.finditer(text):
        name = match.group("name")
        if name in seen:
            continue
        seen.add(name)
        findings.append(VncFinding("security", f"{name} ({match.group('code')})", "offered auth"))
        if name == "None":
            open_display = True
    if open_display:
        findings.append(
            VncFinding("access", "anonymous", "VNC security type None — no password required")
        )

    desktop = _DESKTOP.search(text)
    if desktop is not None:
        findings.append(VncFinding("desktop", desktop.group("v").strip(), "VNC desktop name"))
    return findings


_PARSERS = {"vnc-info": parse_vnc_info}


def parse_vnc_tool(tool: str, text: str) -> list[VncFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
