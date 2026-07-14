from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class MemcachedFinding:
    kind: str  # access | version | items | connections | pid
    value: str
    detail: str = ""
    module: str = "memcached"

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

_VERSION = re.compile(r"Server version:\s*(?P<v>[\w.\-]+)", re.IGNORECASE)
_ITEMS = re.compile(r"Curr items:\s*(?P<v>\d+)", re.IGNORECASE)
_CONNS = re.compile(r"Curr connections:\s*(?P<v>\d+)", re.IGNORECASE)
_PID = re.compile(r"Process ID:\s*(?P<v>\d+)", re.IGNORECASE)


def parse_memcached_info(text: str) -> list[MemcachedFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    version = _VERSION.search(text)
    # only treat the service as answering if memcached-info actually returned stats (a version or a
    # process id); a bare -sV line with no stats block is not enough to claim unauth access.
    pid = _PID.search(text)
    if version is None and pid is None:
        return []
    findings = [MemcachedFinding("access", "unauth", "memcached-info returned without auth")]
    if version is not None:
        findings.append(
            MemcachedFinding("version", version.group("v").strip(), "memcached version")
        )
    items = _ITEMS.search(text)
    if items is not None:
        findings.append(MemcachedFinding("items", items.group("v"), "cached items"))
    conns = _CONNS.search(text)
    if conns is not None:
        findings.append(MemcachedFinding("connections", conns.group("v"), "current connections"))
    return findings


_PARSERS = {"memcached-info": parse_memcached_info}


def parse_memcached_tool(tool: str, text: str) -> list[MemcachedFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
