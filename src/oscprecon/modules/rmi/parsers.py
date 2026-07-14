from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class RmiFinding:
    kind: str  # version | object | endpoint
    value: str
    detail: str = ""
    module: str = "rmi"

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
_SV_LINE = re.compile(
    r"^\d+/tcp\s+open\s+(?:java-rmi|rmiregistry|rmi)\s+(?P<v>.+?)\s*$", re.MULTILINE
)
# a bound-object NAME is a bare identifier line (no dots/spaces); class/impl lines contain dots.
_OBJECT = re.compile(r"^[A-Za-z_][A-Za-z0-9_$\-]*$")
_ENDPOINT = re.compile(r"@(?P<h>[A-Za-z0-9.\-]+):(?P<p>\d+)")
_SKIP = ("implements", "extends", "rmi-dumpregistry", "root object", "@")


def parse_rmi_info(text: str) -> list[RmiFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[RmiFinding] = []

    version = _SV_LINE.search(text)
    if version is not None and version.group("v").strip():
        findings.append(RmiFinding("version", version.group("v").strip(), "RMI registry (banner)"))

    seen_obj: set[str] = set()
    seen_ep: set[str] = set()
    for raw in text.splitlines():
        line = _PREFIX.sub("", raw).strip()
        endpoint = _ENDPOINT.search(line)
        if endpoint is not None:
            ep = f"{endpoint.group('h')}:{endpoint.group('p')}"
            if ep not in seen_ep:
                seen_ep.add(ep)
                findings.append(RmiFinding("endpoint", ep, "RMI object dynamic endpoint"))
        low = line.lower()
        if any(low.startswith(skip) for skip in _SKIP):
            continue
        if _OBJECT.match(line) and line not in seen_obj:
            seen_obj.add(line)
            findings.append(RmiFinding("object", line, "bound RMI object"))
    return findings


_PARSERS = {"rmi-info": parse_rmi_info}


def parse_rmi_tool(tool: str, text: str) -> list[RmiFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
