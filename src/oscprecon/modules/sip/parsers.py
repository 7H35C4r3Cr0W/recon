from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class SipFinding:
    kind: str  # methods | server | version
    value: str
    detail: str = ""
    module: str = "sip"

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

_SIP_VERBS = (
    "INVITE",
    "ACK",
    "CANCEL",
    "BYE",
    "OPTIONS",
    "REGISTER",
    "SUBSCRIBE",
    "NOTIFY",
    "REFER",
    "INFO",
    "PRACK",
    "UPDATE",
    "MESSAGE",
    "PUBLISH",
)
_SERVER = re.compile(r"(?:Server|User-Agent):\s*(?P<v>.+?)\s*$", re.MULTILINE)
# -sV service line fallback, e.g. "5060/udp open  sip  Asterisk PBX".
_SV_LINE = re.compile(r"\bsip\b[ \t]+(?P<v>[A-Za-z].+?)\s*$", re.MULTILINE)


def parse_sip_info(text: str) -> list[SipFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[SipFinding] = []

    # the methods line lists SIP verbs; pick the line carrying the most known verbs so a stray
    # "OPTIONS" elsewhere in the output is never mistaken for the method list.
    best_line, best_hits = "", 0
    for raw in text.splitlines():
        line = re.sub(r"^\s*\|_?\s?", "", raw).strip()
        hits = sum(1 for verb in _SIP_VERBS if re.search(rf"\b{verb}\b", line))
        if hits > best_hits and "," in line:
            best_hits, best_line = hits, line
    if best_hits >= 2:
        findings.append(SipFinding("methods", best_line, "accepted SIP methods"))

    server = _SERVER.search(text)
    if server is not None and server.group("v").strip():
        findings.append(SipFinding("server", server.group("v").strip(), "SIP server / User-Agent"))
    else:
        sv = _SV_LINE.search(text)
        if sv is not None and sv.group("v").strip():
            findings.append(SipFinding("version", sv.group("v").strip()))
    return findings


_PARSERS = {"sip-info": parse_sip_info}


def parse_sip_tool(tool: str, text: str) -> list[SipFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
