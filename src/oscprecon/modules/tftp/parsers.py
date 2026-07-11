from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class TftpFinding:
    kind: str  # file | note
    value: str
    detail: str = ""
    module: str = "tftp"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


# nmap tftp-enum lists each readable file on its own `|`/`|_` line under the `tftp-enum:` header;
# the header carries no filename (@output shows `| tftp-enum:` then a `|_ bootrom.ld` line).
_SKIP_PREFIXES = ("started", "date", "error", "info")


def parse_nmap_tftp(text: str) -> list[TftpFinding]:
    findings: list[TftpFinding] = []
    seen: set[str] = set()
    in_section = False
    for raw in text.splitlines():
        is_script_line = raw.lstrip().startswith("|")
        cleaned = re.sub(r"^\s*\|[_ ]?", "", raw).strip()
        low = cleaned.lower()
        if low.startswith("tftp-enum:"):
            in_section = True
            inline = cleaned.split(":", 1)[1].strip()
            if inline:
                _add_file(findings, seen, inline)
            continue
        if not is_script_line:
            in_section = False
            continue
        if in_section and cleaned and not low.startswith(_SKIP_PREFIXES):
            _add_file(findings, seen, cleaned)
    return findings


def _add_file(findings: list[TftpFinding], seen: set[str], name: str) -> None:
    if name not in seen:
        seen.add(name)
        findings.append(TftpFinding("file", name, "readable via TFTP"))


_PARSERS = {"nmap-tftp": parse_nmap_tftp}


def parse_tftp_tool(tool: str, text: str) -> list[TftpFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
