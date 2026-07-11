from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class IkeFinding:
    kind: str  # service | transform | aggressive | note
    value: str
    detail: str = ""
    module: str = "ike"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


_SA = re.compile(r"SA=\((?P<sa>[^)]*)\)")


def parse_ike_scan(text: str) -> list[IkeFinding]:
    findings: list[IkeFinding] = []
    main = "Main Mode Handshake returned" in text
    aggressive = "Aggressive Mode Handshake returned" in text
    if main:
        findings.append(
            IkeFinding("service", "IKE/ISAKMP VPN (main mode)", "IKEv1 responder present")
        )
    if aggressive:
        findings.append(
            IkeFinding(
                "aggressive",
                "enabled",
                "aggressive mode returns a handshake — the responder leaks PSK-related material",
            )
        )
    if main or aggressive:
        sa = _SA.search(text)
        if sa is not None:
            findings.append(IkeFinding("transform", sa.group("sa").strip()))
    return findings


_PARSERS = {"ike-scan": parse_ike_scan, "ike-scan-aggressive": parse_ike_scan}


def parse_ike_tool(tool: str, text: str) -> list[IkeFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
