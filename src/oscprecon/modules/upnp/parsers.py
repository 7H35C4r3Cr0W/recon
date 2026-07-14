from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class UpnpFinding:
    kind: str  # server | location | device | manufacturer | model
    value: str
    detail: str = ""
    module: str = "upnp"

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

_SERVER = re.compile(r"Server:\s*(?P<v>.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_LOCATION = re.compile(r"Location:\s*(?P<v>https?://\S+)", re.IGNORECASE)
_NAME = re.compile(r"(?:Friendly Name|Name):\s*(?P<v>.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_MANUFACTURER = re.compile(r"Manufacturer:\s*(?P<v>.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_MODEL = re.compile(r"Model(?:\s*Name)?:\s*(?P<v>.+?)\s*$", re.MULTILINE | re.IGNORECASE)


def _first(rx: re.Pattern[str], text: str) -> str:
    match = rx.search(text)
    return match.group("v").strip() if match is not None else ""


def parse_upnp_info(text: str) -> list[UpnpFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[UpnpFinding] = []
    server = _first(_SERVER, text)
    if server:
        findings.append(UpnpFinding("server", server, "UPnP server banner"))
    location = _first(_LOCATION, text)
    if location:
        findings.append(UpnpFinding("location", location, "device description URL"))
    name = _first(_NAME, text)
    if name:
        findings.append(UpnpFinding("device", name, "UPnP device name"))
    manufacturer = _first(_MANUFACTURER, text)
    if manufacturer:
        findings.append(UpnpFinding("manufacturer", manufacturer, "device manufacturer"))
    model = _first(_MODEL, text)
    if model:
        findings.append(UpnpFinding("model", model, "device model"))
    return findings


_PARSERS = {"upnp-info": parse_upnp_info}


def parse_upnp_tool(tool: str, text: str) -> list[UpnpFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
