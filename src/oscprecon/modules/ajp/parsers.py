from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class AjpFinding:
    kind: str  # methods | risky | server | version
    value: str
    detail: str = ""
    module: str = "ajp"

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

_METHODS = re.compile(r"Supported methods:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_RISKY = re.compile(r"Potentially risky methods:\s*(?P<v>.+?)\s*$", re.MULTILINE)
_SERVER = re.compile(r"Server:\s*(?P<v>.+?)\s*$", re.MULTILINE)
# -sV service line fallback, e.g. "8009/tcp open  ajp13  Apache Jserv (Protocol v1.3)".
_SV_LINE = re.compile(r"ajp13[ \t]+(?P<v>.+?)\s*$", re.MULTILINE)


def parse_ajp_info(text: str) -> list[AjpFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[AjpFinding] = []
    methods = _METHODS.search(text)
    if methods is not None and methods.group("v").strip():
        findings.append(AjpFinding("methods", methods.group("v").strip(), "allowed AJP methods"))
    risky = _RISKY.search(text)
    if risky is not None and risky.group("v").strip():
        findings.append(AjpFinding("risky", risky.group("v").strip(), "write-ish AJP methods"))
    server = _SERVER.search(text)
    if server is not None and server.group("v").strip():
        findings.append(AjpFinding("server", server.group("v").strip(), "Server header (via AJP)"))
    if not findings:  # ajp-methods/headers blocked — fall back to the bare -sV product line
        sv = _SV_LINE.search(text)
        if sv is not None and sv.group("v").strip():
            findings.append(AjpFinding("version", sv.group("v").strip()))
    return findings


_PARSERS = {"ajp-info": parse_ajp_info}


def parse_ajp_tool(tool: str, text: str) -> list[AjpFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
