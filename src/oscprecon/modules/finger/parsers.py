from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class FingerFinding:
    kind: str  # user
    value: str
    detail: str = ""
    module: str = "finger"

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

# a finger row starts with a login name, then Name / Tty / Idle / Login-time columns. Header words
# and nmap's own scan lines are skipped so only real login rows become user findings.
_SKIP_FIRST = frozenset(
    {"login", "no", "name", "nmap", "host", "port", "service", "starting", "the", "finger", "not"}
)
_USER_RE = re.compile(r"^(?P<u>[a-z_][a-z0-9_.-]{0,31})$")


def parse_finger_users(text: str) -> list[FingerFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[FingerFinding] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        # strip nmap NSE line prefixes ("| ", "|_") so an embedded finger table parses too
        line = re.sub(r"^\s*\|_?\s?", "", raw).rstrip()
        fields = line.split()
        if len(fields) < 3:  # a real finger row has login + name + tty (+ more)
            continue
        user = fields[0]
        if user.lower() in _SKIP_FIRST or not _USER_RE.match(user) or user in seen:
            continue
        seen.add(user)
        findings.append(FingerFinding("user", user, "logged-in / known user (finger)"))
    return findings


_PARSERS = {"finger-query": parse_finger_users, "finger-nse": parse_finger_users}


def parse_finger_tool(tool: str, text: str) -> list[FingerFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
