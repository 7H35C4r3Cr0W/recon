from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass
class DockerFinding:
    kind: str  # access | version | api | os | containers | images | container
    value: str
    detail: str = ""
    module: str = "docker"

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


def parse_docker_version(text: str) -> list[DockerFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    obj = _loads(text)
    if not isinstance(obj, dict) or not obj.get("Version"):
        return []
    findings = [DockerFinding("access", "unauth", "Docker API answered without authentication")]
    findings.append(DockerFinding("version", str(obj["Version"]), "Docker engine version"))
    if obj.get("ApiVersion"):
        findings.append(DockerFinding("api", str(obj["ApiVersion"]), "Docker API version"))
    if obj.get("Os"):
        findings.append(DockerFinding("os", f"{obj.get('Os')}/{obj.get('Arch', '')}".rstrip("/")))
    return findings


def parse_docker_info(text: str) -> list[DockerFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    obj = _loads(text)
    if not isinstance(obj, dict):
        return []
    findings: list[DockerFinding] = []
    if obj.get("Containers") is not None:
        findings.append(DockerFinding("containers", str(obj["Containers"]), "container count"))
    if obj.get("Images") is not None:
        findings.append(DockerFinding("images", str(obj["Images"]), "image count"))
    if obj.get("OperatingSystem"):
        findings.append(DockerFinding("os", str(obj["OperatingSystem"]), "host OS"))
    return findings


def parse_docker_containers(text: str) -> list[DockerFinding]:
    if not text.strip() or text.lstrip().startswith(_SENTINEL):
        return []
    obj = _loads(text)
    if not isinstance(obj, list):
        return []
    findings: list[DockerFinding] = []
    for container in obj:
        if not isinstance(container, dict):
            continue
        names = container.get("Names") or []
        name = (names[0].lstrip("/") if names else "") or str(container.get("Id", ""))[:12]
        image = str(container.get("Image", ""))
        findings.append(
            DockerFinding("container", f"{name} ({image})".strip(), "running container")
        )
    return findings


_PARSERS = {
    "docker-version": parse_docker_version,
    "docker-info": parse_docker_info,
    "docker-containers": parse_docker_containers,
}


def parse_docker_tool(tool: str, text: str) -> list[DockerFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
