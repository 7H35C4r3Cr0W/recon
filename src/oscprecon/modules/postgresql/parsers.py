from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

DEFAULT_PORT = 5432


@dataclass
class PostgresqlFinding:
    kind: str  # service | version | tls | port
    value: str
    detail: str = ""
    module: str = "postgresql"

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

# There is NO safe unauth PostgreSQL info NSE (only pgsql-brute, which is forbidden), so Tier-1 is
# `nmap -sV` and the only trustworthy evidence is the version-detection service line:
#   `<port>/tcp open  [ssl/]postgresql PostgreSQL DB <version>`
# [ \t] (never \s) so a bare service line cannot bleed the next nmap section's row into the version;
# \b after `postgresql` rejects `pgbouncer` and other look-alikes.
_SVC_LINE = re.compile(
    r"^(?P<port>\d+)/tcp[ \t]+open[ \t]+(?P<tls>ssl/)?postgresql\b"
    r"(?:[ \t]+(?P<rest>\S.*?))?[ \t]*$",
    re.MULTILINE,
)
# strip nmap's `PostgreSQL DB` product prefix to leave the version token (must start with a digit).
_VER = re.compile(r"PostgreSQL(?:\s+DB)?[ \t]*(?P<v>\d[^\r\n]*?\S)?[ \t]*$", re.IGNORECASE)


def parse_postgresql_info(text: str) -> list[PostgresqlFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    match = _SVC_LINE.search(text)
    if match is None:
        return []  # no structural PostgreSQL identification — never trust bare "PostgreSQL" text
    findings = [PostgresqlFinding("service", "PostgreSQL", "nmap -sV service detection")]
    port = int(match.group("port"))
    # emit the port on every identification so suggestions/patterns interpolate the real port;
    # the detail flags a non-standard port (discovered off 5432).
    detail = "standard PostgreSQL port" if port == DEFAULT_PORT else "non-standard PostgreSQL port"
    findings.append(PostgresqlFinding("port", str(port), detail))
    if match.group("tls"):
        findings.append(PostgresqlFinding("tls", "enabled", "TLS-wrapped (ssl/postgresql)"))
    rest = (match.group("rest") or "").strip()
    version = _VER.match(rest)
    if version is not None and version.group("v"):
        findings.append(PostgresqlFinding("version", version.group("v").strip()))
    return findings


# Authenticated catalogue output — `psql -l` and `\\du` print an aligned table whose rows start with
# a leading space and use " | " separators. Read-only: names and role attributes, no row data.
# why: [^|]+? — a `|` is non-whitespace, so a \S-anchored name greedily swallowed the column
# separator itself and reported "webapp    |" as the role name.
_PSQL_ROW = re.compile(r"^\s+(?P<name>[^|]+?)\s*\|(?P<rest>.*)$")


def _psql_rows(text: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for line in text.splitlines():
        match = _PSQL_ROW.match(line.rstrip())
        if match is None:
            continue
        name = match.group("name").strip()
        if not name or name in ("Name", "Role name") or set(name) <= {"-", "+"}:
            continue
        rows.append((name, match.group("rest").strip()))
    return rows


def parse_psql_databases(text: str) -> list[PostgresqlFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    return [
        PostgresqlFinding("database", name, "visible to this account")
        for name, _rest in _psql_rows(text)
        if name not in ("template0", "template1")
    ]


def parse_psql_roles(text: str) -> list[PostgresqlFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    findings: list[PostgresqlFinding] = []
    for name, rest in _psql_rows(text):
        detail = "SUPERUSER" if "superuser" in rest.lower() else rest.split("|")[0].strip()
        findings.append(PostgresqlFinding("role", name, detail))
    return findings


_PARSERS = {
    "postgresql-sv": parse_postgresql_info,
    "psql-databases": parse_psql_databases,
    "psql-roles": parse_psql_roles,
}


def parse_postgresql_tool(tool: str, text: str) -> list[PostgresqlFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
