from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class MongoFinding:
    kind: str  # access | version | database | collection | note
    value: str
    detail: str = ""
    module: str = "mongodb"

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
# mongosh emits ANSI SGR + OSC-title escapes under a pseudo-TTY; non-TTY here, but strip anyway.
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_BANNER = re.compile(
    r"^\s*(MongoDB shell version|connecting to:|Implicit session:|Current Mongosh Log ID:"
    r"|Connecting to:|Using MongoDB:|Using Mongosh:|-{3,}"
    r"|The server generated these startup warnings|.*deprecat)",
    re.IGNORECASE,
)
# getDBNames() asserts on auth: it throws in both shells with the server errmsg, so one regex covers
# mongosh MongoServerError and the legacy "listDatabases failed" block.
_AUTH = re.compile(
    r"requires authentication|not authorized on \w+ to execute"
    r'|codeName"?\s*:\s*"?Unauthorized|Authentication failed|auth(?:entication)? fail',
    re.IGNORECASE,
)
_CONN = re.compile(
    r"ECONNREFUSED|MongoNetworkError|couldn'?t connect|Server selection timed out"
    r"|SocketException|connection attempt failed|No route to host",
    re.IGNORECASE,
)
# OSCP boxes run old MongoDB (3.6, wire v6); modern mongosh refuses it — retry with legacy mongo.
_WIRE = re.compile(r"maximum wire version|requires at least|wireVersion", re.IGNORECASE)
_VERSION = re.compile(r"\bv?(\d+\.\d+\.\d+(?:-[\w.]+)?)")
# our own `print('DB '+n)` prefix is unambiguous, so capture the whole name (spaces/unicode/symbols
# are legal in Mongo names). For collections the db part stays a restricted token (no dots/spaces),
# so an error stack line like `_getErrorWithCode@utils.js:25` can't masquerade as `db.collection`.
_DB_LINE = re.compile(r"^\s*DB (.+?)\s*$", re.MULTILINE)
_COLLECTION = re.compile(r"^\s*([A-Za-z0-9_$-]+)\.(.+?)\s*$")
_MAX_COLLECTIONS = (
    500  # bound the namespace dump; the server's collection list is finite but cap anyway
)

_WIRE_NOTE = MongoFinding(
    "note",
    "wire-version-mismatch",
    "mongosh is newer than this server — retry with the legacy `mongo` shell",
)


def _sanitize(text: str) -> str:
    return _OSC.sub("", _ANSI.sub("", text))


def _skip(text: str) -> bool:
    return not text.strip() or text.lstrip().startswith(_SENTINEL)


def parse_mongo_version(text: str) -> list[MongoFinding]:
    text = _sanitize(text)
    if _skip(text):
        return []
    # the wire note is emitted once, by parse_mongo_databases (every command hits the same error).
    if _WIRE.search(text) or _AUTH.search(text) or _CONN.search(text):
        return []
    # scan every non-banner line (not just the last) so a trailing telemetry/deprecation notice or a
    # leaked "MongoDB server version: X" line still yields the version.
    for line in text.splitlines():
        if not line.strip() or _BANNER.match(line):
            continue
        match = _VERSION.search(line)
        if match is not None:
            return [MongoFinding("version", match.group(1))]
    return []


def parse_mongo_databases(text: str) -> list[MongoFinding]:
    text = _sanitize(text)
    if _skip(text):
        return []
    if _WIRE.search(text):
        return [_WIRE_NOTE]
    if _AUTH.search(text):
        return [
            MongoFinding("access", "auth-required", "listDatabases refused without credentials")
        ]
    if _CONN.search(text):
        return []
    names: list[str] = []
    for match in _DB_LINE.finditer(text):
        name = match.group(1)
        if name not in names:
            names.append(name)
    if not names:
        return []
    findings = [MongoFinding("access", "unauth", "listDatabases returned without authentication")]
    findings.extend(MongoFinding("database", name) for name in names)
    return findings


def parse_mongo_collections(text: str) -> list[MongoFinding]:
    text = _sanitize(text)
    if _skip(text):
        return []
    # access + the wire note come from parse_mongo_databases; collections only adds the namespace.
    if _WIRE.search(text) or _AUTH.search(text) or _CONN.search(text):
        return []
    findings: list[MongoFinding] = []
    seen: set[str] = set()
    for line in text.splitlines():
        match = _COLLECTION.match(line)
        if match is None:
            continue
        value = f"{match.group(1)}.{match.group(2)}"
        if value in seen:
            continue
        seen.add(value)
        findings.append(MongoFinding("collection", value))
        if len(findings) >= _MAX_COLLECTIONS:
            findings.append(
                MongoFinding("note", "collections-truncated", f"capped at {_MAX_COLLECTIONS}")
            )
            break
    return findings


_PARSERS = {
    "mongodb-version": parse_mongo_version,
    "mongodb-databases": parse_mongo_databases,
    "mongodb-collections": parse_mongo_collections,
}


def parse_mongo_tool(tool: str, text: str) -> list[MongoFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
