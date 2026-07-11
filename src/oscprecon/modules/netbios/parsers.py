from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class NetbiosFinding:
    kind: str  # hostname | domain | role | user | mac
    value: str
    detail: str = ""
    module: str = "netbios"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


# nmblookup -A row: `NAME  <XX> - [<GROUP>] <nodetype> <ACTIVE>`. The <XX> suffix is the NetBIOS
# service code that tells us what the name is (see below).
_NBT_ROW = re.compile(
    r"^\s*(?P<name>\S.*?)\s+<(?P<suffix>[0-9A-Fa-f]{2})>\s+-\s+"
    r"(?P<group><GROUP>\s+)?[BHMP]\s+<ACTIVE>",
)
_MAC = re.compile(r"MAC Address\s*=\s*(?P<mac>[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})")
# NetBIOS suffix codes worth naming a role for.
_ROLE_SUFFIXES = {
    "20": "file-server (SMB)",
    "1c": "domain-controllers",
    "1b": "domain-master-browser (PDC)",
}


def parse_nmblookup(text: str) -> list[NetbiosFinding]:
    findings: list[NetbiosFinding] = []
    hostnames: set[str] = set()
    seen: set[tuple[str, str]] = set()

    def _add(kind: str, value: str, detail: str = "") -> None:
        key = (kind, value)
        if value and key not in seen:
            seen.add(key)
            findings.append(NetbiosFinding(kind, value, detail))

    for raw in text.splitlines():
        row = _NBT_ROW.match(raw)
        if row is None:
            continue
        name = row.group("name").strip()
        suffix = row.group("suffix").lower()
        is_group = row.group("group") is not None
        if name == "__MSBROWSE__":
            continue
        if suffix == "00":
            if is_group:
                _add("domain", name, "workgroup / domain")
            else:
                hostnames.add(name)
                _add("hostname", name)
        elif suffix in _ROLE_SUFFIXES:
            _add("role", _ROLE_SUFFIXES[suffix], name)
            if suffix in {"1c", "1b"}:  # a DC name is also the AD domain
                _add("domain", name, "AD domain (from DC suffix)")
        elif suffix == "03" and name not in hostnames:
            _add("user", name, "NetBIOS messenger name — possible logged-in user")
    mac = _MAC.search(text)
    if mac is not None:
        _add("mac", mac.group("mac"))
    return findings


_NBTSCAN_MAC = re.compile(r"[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5}")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def parse_nbtscan(text: str) -> list[NetbiosFinding]:
    findings: list[NetbiosFinding] = []
    seen: set[tuple[str, str]] = set()

    def _add(kind: str, value: str, detail: str = "") -> None:
        key = (kind, value)
        if value and key not in seen:
            seen.add(key)
            findings.append(NetbiosFinding(kind, value, detail))

    for raw in text.splitlines():
        tokens = raw.split()
        if len(tokens) < 2 or not _IPV4.match(tokens[0]):
            continue
        _add("hostname", tokens[1])
        if "<server>" in raw:
            _add("role", "file-server (SMB)", tokens[1])
        mac = _NBTSCAN_MAC.search(raw)
        if mac is not None:
            _add("mac", mac.group(0))
    return findings


_PARSERS = {"nmblookup": parse_nmblookup, "nbtscan": parse_nbtscan}


def parse_netbios_tool(tool: str, text: str) -> list[NetbiosFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
