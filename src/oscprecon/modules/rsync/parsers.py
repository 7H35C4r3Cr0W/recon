from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class RsyncFinding:
    kind: str  # module | access
    value: str
    detail: str = ""
    module: str = "rsync"

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
# protocol / error / nmap-scaffold lines that are never a module name
_NOISE = (
    "@rsyncd",
    "@error",
    "rsync:",
    "rsync error",
    "port",
    "nmap",
    "host",
    "service",
    "starting",
)
_MODULE_NAME = re.compile(r"^(?P<m>[A-Za-z0-9_][A-Za-z0-9_.\-]{0,63})$")


def parse_rsync_modules(text: str) -> list[RsyncFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    modules: list[RsyncFinding] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        # strip nmap NSE prefixes ("| ", "|_") so an embedded module list parses too
        line = re.sub(r"^\s*\|_?\s?", "", raw).strip()
        if not line or line.lower().startswith(_NOISE):
            continue
        # a module row is "<name>" or "<name>\t<comment>" / "<name>  <comment>"
        name = re.split(r"[\t ]{1,}", line, maxsplit=1)[0]
        if not _MODULE_NAME.match(name) or name in seen:
            continue
        seen.add(name)
        modules.append(RsyncFinding("module", name, "exposed rsync module"))
    if modules:
        modules.insert(0, RsyncFinding("access", "unauth", "modules listed without authentication"))
    return modules


_PARSERS = {"rsync-modules": parse_rsync_modules, "rsync-nmap": parse_rsync_modules}


def parse_rsync_tool(tool: str, text: str) -> list[RsyncFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
