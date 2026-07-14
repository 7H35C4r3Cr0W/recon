from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class MdnsFinding:
    kind: str  # service | address
    value: str
    detail: str = ""
    module: str = "mdns"

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
_PREFIX = re.compile(r"^\s*\|_?\s?")
# an advertised service row: "<port>/<proto> <service-name>", e.g. "22/tcp ssh".
_SERVICE = re.compile(r"^(?P<port>\d{1,5})/(?P<proto>tcp|udp)\s+(?P<name>\S.*?)$", re.IGNORECASE)
_ADDRESS = re.compile(r"Address=\s*(?P<a>[0-9a-fA-F:.]+)")


def parse_mdns_info(text: str) -> list[MdnsFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[MdnsFinding] = []
    seen_svc: set[str] = set()
    seen_addr: set[str] = set()
    for raw in text.splitlines():
        line = _PREFIX.sub("", raw).strip()
        svc = _SERVICE.match(line)
        if svc is not None:
            value = (
                f"{svc.group('name').strip()} ({svc.group('port')}/{svc.group('proto').lower()})"
            )
            if value not in seen_svc:
                seen_svc.add(value)
                findings.append(MdnsFinding("service", value, "advertised via mDNS"))
            continue
        addr = _ADDRESS.search(line)
        if addr is not None and addr.group("a") not in seen_addr:
            seen_addr.add(addr.group("a"))
            findings.append(MdnsFinding("address", addr.group("a"), "host address (mDNS)"))
    return findings


_PARSERS = {"mdns-info": parse_mdns_info}


def parse_mdns_tool(tool: str, text: str) -> list[MdnsFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
