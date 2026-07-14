from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class SvnFinding:
    kind: str  # access | entry | version | uuid | revision
    value: str
    detail: str = ""
    module: str = "svn"

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

_UUID = re.compile(r"Repository UUID:\s*(?P<v>[\w\-]+)", re.IGNORECASE)
_REV = re.compile(r"(?:Last changed rev|Revision|rev):\s*(?P<v>\d+)", re.IGNORECASE)
_SV_LINE = re.compile(r"^\d+/tcp\s+open\s+(?:svnserve|subversion)\s+(?P<v>.+?)\s*$", re.MULTILINE)


def parse_svn_ls(text: str) -> list[SvnFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    entries: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        # `svn:` prefixes an auth/error message — a real listing row is a bare name (dirs end in /)
        if not line or line.lower().startswith("svn:"):
            continue
        entries.append(line)
    if not entries:
        return []
    findings = [SvnFinding("access", "anonymous", "svn ls returned without authentication")]
    findings.extend(SvnFinding("entry", entry, "repo entry") for entry in entries)
    return findings


def parse_svn_nmap(text: str) -> list[SvnFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[SvnFinding] = []
    version = _SV_LINE.search(text)
    if version is not None and version.group("v").strip():
        findings.append(SvnFinding("version", version.group("v").strip(), "svnserve (banner)"))
    uuid = _UUID.search(text)
    if uuid is not None:
        findings.append(SvnFinding("uuid", uuid.group("v"), "repository UUID"))
    rev = _REV.search(text)
    if rev is not None:
        findings.append(SvnFinding("revision", rev.group("v"), "latest revision"))
    return findings


_PARSERS = {"svn-ls": parse_svn_ls, "svn-nmap": parse_svn_nmap}


def parse_svn_tool(tool: str, text: str) -> list[SvnFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
