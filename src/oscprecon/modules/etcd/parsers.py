from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass
class EtcdFinding:
    kind: str  # access | version | member | key
    value: str
    detail: str = ""
    module: str = "etcd"

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
# etcd signals auth-required with an HTTP 401 or its own message — match those, NOT a bare "auth: "
# substring, which false-fired on legitimate key data containing "oauth:"/"auth: enabled" and then
# silently dropped every finding.
_AUTH_ERR = re.compile(
    r"401 Unauthorized|requires user authentication|Insufficient credentials", re.IGNORECASE
)


def _loads(text: str) -> Any:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def parse_etcd_version(text: str) -> list[EtcdFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL) or _AUTH_ERR.search(text):
        return []
    obj = _loads(text)
    if not isinstance(obj, dict) or not obj.get("etcdserver"):
        return []
    return [
        EtcdFinding("access", "unauth", "etcd API answered without authentication"),
        EtcdFinding("version", str(obj["etcdserver"]), "etcd server version"),
    ]


def parse_etcd_members(text: str) -> list[EtcdFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL) or _AUTH_ERR.search(text):
        return []
    obj = _loads(text)
    if not isinstance(obj, dict):
        return []
    members = obj.get("members")
    findings: list[EtcdFinding] = []
    if isinstance(members, list):
        for member in members:
            if isinstance(member, dict) and member.get("name"):
                findings.append(EtcdFinding("member", str(member["name"]), "etcd cluster member"))
    return findings


def parse_etcd_keys(text: str) -> list[EtcdFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL) or _AUTH_ERR.search(text):
        return []
    obj = _loads(text)
    # etcd >= 3.4 disables v2 -> {"errorCode":...}; only a successful get exposes keys
    if not isinstance(obj, dict) or obj.get("action") != "get":
        return []
    node = obj.get("node")
    if not isinstance(node, dict):
        return []
    findings = [EtcdFinding("access", "unauth", "v2 keys readable without authentication")]
    for child in node.get("nodes", []) or []:
        if isinstance(child, dict) and child.get("key"):
            findings.append(EtcdFinding("key", str(child["key"]), "etcd key"))
    return findings


_PARSERS = {
    "etcd-version": parse_etcd_version,
    "etcd-members": parse_etcd_members,
    "etcd-keys": parse_etcd_keys,
}


def parse_etcd_tool(tool: str, text: str) -> list[EtcdFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
