from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass
class ElasticFinding:
    kind: str  # access | version | cluster | index | status | nodes
    value: str
    detail: str = ""
    module: str = "elasticsearch"

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
_AUTH_ERR = re.compile(r"security_exception|missing authentication|401 Unauthorized", re.IGNORECASE)


def _loads(text: str) -> dict[str, Any] | None:
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


def parse_elastic_root(text: str) -> list[ElasticFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    if _AUTH_ERR.search(text):
        return [ElasticFinding("access", "auth-required", "root refused without credentials")]
    obj = _loads(text)
    if obj is None:
        return []
    findings = [ElasticFinding("access", "unauth", "root JSON returned without authentication")]
    version = obj.get("version")
    if isinstance(version, dict) and version.get("number"):
        findings.append(ElasticFinding("version", str(version["number"])))
    if obj.get("cluster_name"):
        findings.append(ElasticFinding("cluster", str(obj["cluster_name"]), "cluster name"))
    return findings


def parse_elastic_indices(text: str) -> list[ElasticFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL) or _AUTH_ERR.search(text):
        return []
    findings: list[ElasticFinding] = []
    for line in text.splitlines():
        fields = line.split()
        # rows look like: "green open <index> <uuid> ..."; skip the header and blank lines
        if len(fields) < 3 or fields[0] not in {"green", "yellow", "red"}:
            continue
        findings.append(ElasticFinding("index", fields[2], "Elasticsearch index"))
    return findings


def parse_elastic_health(text: str) -> list[ElasticFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL) or _AUTH_ERR.search(text):
        return []
    obj = _loads(text)
    if obj is None:
        return []
    findings: list[ElasticFinding] = []
    if obj.get("status"):
        findings.append(ElasticFinding("status", str(obj["status"]), "cluster health"))
    if obj.get("number_of_nodes") is not None:
        findings.append(ElasticFinding("nodes", str(obj["number_of_nodes"]), "node count"))
    return findings


_PARSERS = {
    "es-root": parse_elastic_root,
    "es-indices": parse_elastic_indices,
    "es-health": parse_elastic_health,
}


def parse_elastic_tool(tool: str, text: str) -> list[ElasticFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
