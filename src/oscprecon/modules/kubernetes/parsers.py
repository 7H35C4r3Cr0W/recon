from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass
class KubeFinding:
    kind: str  # access | version | api | healthz
    value: str
    detail: str = ""
    module: str = "kubernetes"

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


def _loads(text: str) -> Any:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def parse_kube_version(text: str) -> list[KubeFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    obj = _loads(text)
    if not isinstance(obj, dict) or not obj.get("gitVersion"):
        return []
    return [KubeFinding("version", str(obj["gitVersion"]), "Kubernetes API server version")]


def parse_kube_api(text: str) -> list[KubeFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    obj = _loads(text)
    if not isinstance(obj, dict):
        return []
    # a 403 Status body means anonymous is denied; an APIVersions body means anonymous is allowed
    if obj.get("kind") == "Status" and obj.get("code") in (401, 403):
        return [KubeFinding("access", "forbidden", "anonymous access denied by the API server")]
    if obj.get("kind") == "APIVersions" or "versions" in obj:
        versions = obj.get("versions")
        detail = f"anonymous access allowed (versions: {', '.join(versions)})" if versions else ""
        return [KubeFinding("access", "anonymous", detail or "anonymous access allowed")]
    return []


def parse_kube_healthz(text: str) -> list[KubeFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    if text.strip().lower() == "ok":
        return [KubeFinding("healthz", "ok", "API server healthy")]
    return []


_PARSERS = {
    "k8s-version": parse_kube_version,
    "k8s-api": parse_kube_api,
    "k8s-healthz": parse_kube_healthz,
}


def parse_kube_tool(tool: str, text: str) -> list[KubeFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
