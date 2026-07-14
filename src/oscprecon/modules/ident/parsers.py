from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class IdentFinding:
    kind: str  # version | user
    value: str
    detail: str = ""
    module: str = "ident"

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

_SV_LINE = re.compile(r"^\d+/tcp\s+open\s+(?:ident|auth)\??\s+(?P<v>.+?)\s*$", re.MULTILINE)
_PREFIX = re.compile(r"^\s*\|_?\s?")  # nmap NSE line prefix ("| " / "|_")
_USERNAME = re.compile(r"^[A-Za-z0-9_][\w\-]*$")


def _strip(line: str) -> str:
    return _PREFIX.sub("", line).strip()


def parse_ident_info(text: str) -> list[IdentFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[IdentFinding] = []

    version = _SV_LINE.search(text)
    if version is not None and version.group("v").strip():
        findings.append(
            IdentFinding("version", version.group("v").strip(), "ident daemon (banner)")
        )

    # auth-owners prints the owning user inline after the colon, or on the next line. Scan line by
    # line so a following "auth-owners:" header is never mistaken for an owner value.
    lines = text.splitlines()
    seen: set[str] = set()
    for index, raw in enumerate(lines):
        line = _strip(raw)
        if "auth-owners:" not in line.lower():
            continue
        candidate = line.split(":", 1)[1].strip()
        if not candidate and index + 1 < len(lines):
            candidate = _strip(lines[index + 1])
        if _USERNAME.match(candidate) and candidate not in seen:
            seen.add(candidate)
            findings.append(IdentFinding("user", candidate, "service owner via ident"))
    return findings


_PARSERS = {"ident-info": parse_ident_info}


def parse_ident_tool(tool: str, text: str) -> list[IdentFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
