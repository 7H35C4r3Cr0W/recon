from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class MysqlFinding:
    kind: str  # version | protocol | auth-plugin
    value: str
    detail: str = ""
    module: str = "mysql"

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

# mysql-info is an unauth pre-login handshake leak; fields below map that nmap NSE output. The
# [| \t] char-classes (not \s) keep each field on its own physical line so a value can't bleed
# across the newline into the next table row (the bug the MSSQL review caught).
_VERSION_FIELD = re.compile(r"^[| \t]*Version:[ \t]*(?P<v>.+?)\s*$", re.MULTILINE)
_PROTOCOL = re.compile(r"^[| \t]*Protocol:[ \t]*(?P<v>\d+)\s*$", re.MULTILINE)
_AUTH_PLUGIN = re.compile(r"Auth Plugin Name:[ \t]*(?P<v>\S+)\s*$", re.MULTILINE)
# (?:ssl/)? so a TLS-wrapped banner (nmap prints `ssl/mysql`) still yields a version on fallback.
_SVC_LINE = re.compile(r"open[ \t]+(?:ssl/)?mysql[ \t]+(?P<v>\S.*?)\s*$", re.MULTILINE)


def _first(rx: re.Pattern[str], text: str) -> str:
    match = rx.search(text)
    return match.group("v").strip() if match is not None else ""


def parse_mysql_info(text: str) -> list[MysqlFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[MysqlFinding] = []
    # version: prefer the structured mysql-info Version field, else the bare -sV service line.
    version = _first(_VERSION_FIELD, text) or _first(_SVC_LINE, text)
    if version:
        findings.append(MysqlFinding("version", version))
    protocol = _first(_PROTOCOL, text)
    if protocol:
        findings.append(MysqlFinding("protocol", protocol, "MySQL wire-protocol version"))
    auth_plugin = _first(_AUTH_PLUGIN, text)
    if auth_plugin:
        findings.append(MysqlFinding("auth-plugin", auth_plugin, "default authentication plugin"))
    return findings


# Authenticated catalogue output (`mysql -e 'SHOW DATABASES'`) — tab-separated with a header row.
# Only names and grants are read; nothing is written and no row data is touched.
_MYSQL_NOISE = ("Database", "information_schema", "performance_schema", "sys", "+--", "|")


def parse_mysql_databases(text: str) -> list[MysqlFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[MysqlFinding] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(_MYSQL_NOISE):
            continue
        if line.upper().startswith(("ERROR", "MYSQL:")):
            continue  # a refusal is not a database name
        name = line.split("\t")[0].strip()
        if not name or " " in name:
            continue
        findings.append(MysqlFinding("database", name, "readable by this account"))
    return findings


def parse_mysql_grants(text: str) -> list[MysqlFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[MysqlFinding] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.upper().startswith("GRANT "):
            detail = "FULL PRIVILEGES" if "ALL PRIVILEGES" in line.upper() else ""
            findings.append(MysqlFinding("grant", line, detail))
        elif "\t" in line and not line.startswith(("user", "Grants")):
            user, _, host = line.partition("\t")
            if user.strip():
                findings.append(MysqlFinding("account", f"{user.strip()}@{host.strip()}"))
    return findings


_PARSERS = {
    "mysql-info": parse_mysql_info,
    "mysql-databases": parse_mysql_databases,
    "mysql-grants": parse_mysql_grants,
}


def parse_mysql_tool(tool: str, text: str) -> list[MysqlFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
