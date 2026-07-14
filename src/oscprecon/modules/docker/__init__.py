from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.docker.parsers import (
    DockerFinding,
    parse_docker_containers,
    parse_docker_info,
    parse_docker_tool,
    parse_docker_version,
)

__all__ = [
    "DOCKER_SERVICE_NAMES",
    "DockerFinding",
    "DockerModule",
    "DockerStep",
    "parse_docker_containers",
    "parse_docker_info",
    "parse_docker_tool",
    "parse_docker_version",
]

DOCKER_SERVICE_NAMES = frozenset({"docker"})
_DOCKER_PORTS = frozenset({2375, 2376})
_DEFAULT_PORT = 2375
# All reads are unauthenticated HTTP GETs on the Docker remote API (read-only). Only GET endpoints
# are wrapped — container create / exec is code execution, not recon, and is never issued.


@dataclass
class DockerStep:
    command: Command
    tool: str = ""


class DockerModule(Module):
    name = "docker"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in DOCKER_SERVICE_NAMES or s.port in _DOCKER_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[DockerStep]:
        base = f"http://{target.ip}:{port or _DEFAULT_PORT}"
        return [
            DockerStep(
                Command(
                    "docker",
                    f"curl -s {base}/version",
                    "Engine + API version, OS/arch (unauth read-only).",
                    "< 30s",
                    "docker/version.json",
                ),
                "docker-version",
            ),
            DockerStep(
                Command(
                    "docker",
                    f"curl -s {base}/info",
                    "Host info — container/image counts, name, OS (read-only).",
                    "< 30s",
                    "docker/info.json",
                ),
                "docker-info",
            ),
            DockerStep(
                Command(
                    "docker",
                    f"curl -s {base}/containers/json",
                    "Running containers — names + images (read-only).",
                    "< 30s",
                    "docker/containers.json",
                ),
                "docker-containers",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for df in parse_docker_tool(tool, text):
                findings.append(
                    Finding(
                        service="docker",
                        title=f"{df.kind}: {df.value}",
                        detail=df.detail,
                        fields={"kind": df.kind, "value": df.value, "detail": df.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind"): f.fields.get("value", "") for f in findings}
        if kinds.get("access") == "unauth":
            return [
                "The Docker remote API answers unauthenticated — this is full host control. "
                "Enumerate images read-only (`curl -s {target}:2375/images/json`); container "
                "create/exec is code execution and out of scope for this recon tool."
            ]
        return []
