from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.kubernetes.parsers import (
    KubeFinding,
    parse_kube_api,
    parse_kube_healthz,
    parse_kube_tool,
    parse_kube_version,
)

__all__ = [
    "KUBE_SERVICE_NAMES",
    "KubeFinding",
    "KubernetesModule",
    "KubeStep",
    "parse_kube_api",
    "parse_kube_healthz",
    "parse_kube_tool",
    "parse_kube_version",
]

KUBE_SERVICE_NAMES = frozenset({"kube-apiserver", "kubernetes", "sun-sr-https"})
_KUBE_PORTS = frozenset({6443, 8443, 10250})
_DEFAULT_PORT = 6443
# The API server speaks TLS, so -k skips the cluster's self-signed cert. Every wrapped call is a
# read-only GET; anonymous access to /api or the kubelet /pods is the exposure we are checking for.


@dataclass
class KubeStep:
    command: Command
    tool: str = ""


class KubernetesModule(Module):
    name = "kubernetes"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in KUBE_SERVICE_NAMES or s.port in _KUBE_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[KubeStep]:
        base = f"https://{target.ip}:{port or _DEFAULT_PORT}"
        return [
            KubeStep(
                Command(
                    "kubernetes",
                    f"curl -sk {base}/version",
                    "API server version (gitVersion) — read-only, no auth.",
                    "< 30s",
                    "kubernetes/version.json",
                ),
                "k8s-version",
            ),
            KubeStep(
                Command(
                    "kubernetes",
                    f"curl -sk {base}/api",
                    "API groups — a 200 means anonymous access is allowed (read-only).",
                    "< 30s",
                    "kubernetes/api.json",
                ),
                "k8s-api",
            ),
            KubeStep(
                Command(
                    "kubernetes",
                    f"curl -sk {base}/healthz",
                    "Health endpoint (read-only).",
                    "< 30s",
                    "kubernetes/healthz.txt",
                ),
                "k8s-healthz",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for kf in parse_kube_tool(tool, text):
                findings.append(
                    Finding(
                        service="kubernetes",
                        title=f"{kf.kind}: {kf.value}",
                        detail=kf.detail,
                        fields={"kind": kf.kind, "value": kf.value, "detail": kf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind"): f.fields.get("value", "") for f in findings}
        if kinds.get("access") == "anonymous":
            return [
                "The Kubernetes API allows anonymous access — enumerate resources read-only "
                "(`curl -sk {target}:6443/api/v1/namespaces`); check the kubelet on 10250."
            ]
        if kinds.get("access") == "forbidden":
            return ["Kubernetes API reachable but anonymous is forbidden — note the version only."]
        return []
