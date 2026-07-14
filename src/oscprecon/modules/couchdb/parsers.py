from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass
class CouchFinding:
    kind: str  # access | version | database | node
    value: str
    detail: str = ""
    module: str = "couchdb"

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
_AUTH_ERR = re.compile(r'"error"\s*:\s*"unauthorized"|401 Unauthorized', re.IGNORECASE)


def _loads(text: str) -> Any:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def parse_couch_root(text: str) -> list[CouchFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    if _AUTH_ERR.search(text):
        return [CouchFinding("access", "auth-required", "root refused without credentials")]
    obj = _loads(text)
    if not isinstance(obj, dict) or obj.get("couchdb") is None:
        return []
    findings: list[CouchFinding] = []
    if obj.get("version"):
        findings.append(CouchFinding("version", str(obj["version"]), "CouchDB version"))
    return findings


def parse_couch_dbs(text: str) -> list[CouchFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL) or _AUTH_ERR.search(text):
        return []
    obj = _loads(text)
    if not isinstance(obj, list):
        return []
    # a list returned without a 401 means "admin party" — unauthenticated database access
    findings = [CouchFinding("access", "unauth", "_all_dbs returned without authentication")]
    for name in obj:
        findings.append(CouchFinding("database", str(name), "CouchDB database"))
    return findings


def parse_couch_membership(text: str) -> list[CouchFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL) or _AUTH_ERR.search(text):
        return []
    obj = _loads(text)
    if not isinstance(obj, dict):
        return []
    nodes = obj.get("cluster_nodes")
    findings: list[CouchFinding] = []
    if isinstance(nodes, list):
        for node in nodes:
            findings.append(CouchFinding("node", str(node), "cluster node"))
    return findings


_PARSERS = {
    "couch-root": parse_couch_root,
    "couch-dbs": parse_couch_dbs,
    "couch-membership": parse_couch_membership,
}


def parse_couch_tool(tool: str, text: str) -> list[CouchFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
