from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class IppFinding:
    kind: str  # version | printer
    value: str
    detail: str = ""
    module: str = "ipp"

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

_VERSION = re.compile(r"CUPS[ /]?(?P<v>\d+\.\d[\w.]*)", re.IGNORECASE)
# a cups-queue-info line names a printer then its state: "HP_LaserJet (idle)" (nmap "|" prefix
# is stripped per-line before matching).
_QUEUE = re.compile(
    r"^(?P<p>[A-Za-z0-9_][\w\-]*)\s*\((?:idle|processing|stopped|paused|disabled)\)",
    re.IGNORECASE,
)
# the /printers/ web page links each printer as /printers/<name>.
_HREF = re.compile(r"/printers/(?P<p>[A-Za-z0-9_][\w\-]*)")


def parse_ipp_nmap(text: str) -> list[IppFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[IppFinding] = []
    version = _VERSION.search(text)
    if version is not None:
        findings.append(IppFinding("version", f"CUPS {version.group('v')}", "CUPS server version"))
    for raw in text.splitlines():
        line = re.sub(r"^\s*\|_?\s?", "", raw).strip()  # drop the nmap NSE line prefix
        match = _QUEUE.match(line)
        if match is None or match.group("p").lower() in {"open", "state", "queue"}:
            continue
        findings.append(IppFinding("printer", match.group("p"), line))
    return findings


def parse_ipp_curl(text: str) -> list[IppFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[IppFinding] = []
    seen: set[str] = set()
    for match in _HREF.finditer(text):
        name = match.group("p")
        if name in seen:
            continue
        seen.add(name)
        findings.append(IppFinding("printer", name, "CUPS printer (web UI)"))
    return findings


_PARSERS = {"ipp-nmap": parse_ipp_nmap, "ipp-curl": parse_ipp_curl}


def parse_ipp_tool(tool: str, text: str) -> list[IppFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
