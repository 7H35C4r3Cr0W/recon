from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class X11Finding:
    kind: str  # access | version
    value: str
    detail: str = ""
    module: str = "x11"

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

_GRANTED = re.compile(r"X server access is granted", re.IGNORECASE)
_DENIED = re.compile(r"X server access is denied", re.IGNORECASE)
# -sV service line fallback, e.g. "6000/tcp open  X11  (access denied)".
_SV_LINE = re.compile(r"\bX11\b[ \t]+(?P<v>.+?)\s*$", re.MULTILINE)


def parse_x11_access(text: str) -> list[X11Finding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[X11Finding] = []
    if _GRANTED.search(text):
        # an open X display is an unauthenticated exposure — flagged like other anonymous access.
        findings.append(
            X11Finding("access", "anonymous", "X server access granted — no authentication")
        )
    elif _DENIED.search(text):
        findings.append(X11Finding("access", "denied", "X server access denied"))
    sv = _SV_LINE.search(text)
    if sv is not None and sv.group("v").strip() and "access" not in sv.group("v").lower():
        findings.append(X11Finding("version", sv.group("v").strip()))
    return findings


_PARSERS = {"x11-access": parse_x11_access}


def parse_x11_tool(tool: str, text: str) -> list[X11Finding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
