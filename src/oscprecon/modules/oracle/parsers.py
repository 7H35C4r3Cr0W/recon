from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class OracleFinding:
    kind: str  # version
    value: str
    detail: str = ""
    module: str = "oracle"

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

# oracle-tns-version prints "Version: <n>"; the -sV line reads "oracle-tns Oracle TNS Listener <n>".
_NSE_VERSION = re.compile(r"\bVersion:\s*(?P<v>[\d.]+)", re.MULTILINE)
_SV_VERSION = re.compile(r"Oracle TNS Listener\s+(?P<v>[\d.]+)")
_SV_LINE = re.compile(r"oracle-tns[ \t]+(?P<v>.+?)\s*$", re.MULTILINE)


def parse_oracle_info(text: str) -> list[OracleFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    version = ""
    nse = _NSE_VERSION.search(text)
    sv = _SV_VERSION.search(text)
    if nse is not None:
        version = nse.group("v").strip()
    elif sv is not None:
        version = sv.group("v").strip()
    if version:
        return [OracleFinding("version", version, "Oracle TNS listener version")]
    # no structured version — fall back to the bare -sV product line
    line = _SV_LINE.search(text)
    if line is not None and line.group("v").strip():
        return [OracleFinding("version", line.group("v").strip())]
    return []


_PARSERS = {"oracle-info": parse_oracle_info}


def parse_oracle_tool(tool: str, text: str) -> list[OracleFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
