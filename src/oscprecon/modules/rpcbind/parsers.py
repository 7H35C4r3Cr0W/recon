from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class RpcbindFinding:
    kind: str  # access | program
    value: str
    detail: str = ""
    module: str = "rpcbind"

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
# a program row starts with the 6-digit RPC program number (rpcinfo AND nmap rpcinfo share this).
_PROGRAM_ROW = re.compile(r"^\d{5,7}\b")
_SERVICE_NAME = re.compile(r"^[A-Za-z][\w\-]*$")
_PORTPROTO = re.compile(r"(?P<port>\d+)/(?P<proto>tcp|udp)")


def parse_rpcinfo(text: str) -> list[RpcbindFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    programs: list[RpcbindFinding] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = _PREFIX.sub("", raw).strip()
        if not _PROGRAM_ROW.match(line):
            continue
        tokens = line.split()
        service = tokens[-1]
        # the last column is the service name; skip rows that end in a bare number (no name column)
        if not _SERVICE_NAME.match(service) or service in seen:
            continue
        seen.add(service)
        detail = line
        port = _PORTPROTO.search(line)
        if port is not None:
            detail = f"{port.group('port')}/{port.group('proto')}"
        programs.append(RpcbindFinding("program", service, detail))
    if not programs:
        return []
    return [
        RpcbindFinding("access", "unauth", "portmapper answered without authentication"),
        *programs,
    ]


_PARSERS = {"rpcbind-rpcinfo": parse_rpcinfo, "rpcbind-nmap": parse_rpcinfo}


def parse_rpcbind_tool(tool: str, text: str) -> list[RpcbindFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
