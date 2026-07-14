from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.etcd.parsers import (
    EtcdFinding,
    parse_etcd_keys,
    parse_etcd_members,
    parse_etcd_tool,
    parse_etcd_version,
)

__all__ = [
    "ETCD_SERVICE_NAMES",
    "EtcdFinding",
    "EtcdModule",
    "EtcdStep",
    "parse_etcd_keys",
    "parse_etcd_members",
    "parse_etcd_tool",
    "parse_etcd_version",
]

ETCD_SERVICE_NAMES = frozenset({"etcd", "etcd-client", "etcd-server"})
_ETCD_PORTS = frozenset({2379, 2380})
_DEFAULT_PORT = 2379
# All reads are unauthenticated HTTP GETs on the etcd client API (read-only). A secured/mTLS etcd
# refuses or needs a client cert; the v2 keys API is disabled by default on etcd >= 3.4 (404).


@dataclass
class EtcdStep:
    command: Command
    tool: str = ""


class EtcdModule(Module):
    name = "etcd"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in ETCD_SERVICE_NAMES or s.port in _ETCD_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[EtcdStep]:
        base = f"http://{target.ip}:{port or _DEFAULT_PORT}"
        return [
            EtcdStep(
                Command(
                    "etcd",
                    f"curl -s {base}/version",
                    "etcd server + cluster version (unauth read-only).",
                    "< 30s",
                    "etcd/version.json",
                ),
                "etcd-version",
            ),
            EtcdStep(
                Command(
                    "etcd",
                    f"curl -s {base}/v2/members",
                    "Cluster members + their client URLs (read-only).",
                    "< 30s",
                    "etcd/members.json",
                ),
                "etcd-members",
            ),
            EtcdStep(
                Command(
                    "etcd",
                    f"curl -s {base}/v2/keys",
                    "v2 key list — top-level keys if the v2 API is enabled + unauth (read-only).",
                    "< 30s",
                    "etcd/keys.json",
                ),
                "etcd-keys",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        seen: set[tuple[str, str]] = set()
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for ef in parse_etcd_tool(tool, text):
                if (ef.kind, ef.value) in seen:
                    continue
                seen.add((ef.kind, ef.value))
                findings.append(
                    Finding(
                        service="etcd",
                        title=f"{ef.kind}: {ef.value}",
                        detail=ef.detail,
                        fields={"kind": ef.kind, "value": ef.value, "detail": ef.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind"): f.fields.get("value", "") for f in findings}
        if kinds.get("access") == "unauth" or "key" in kinds:
            return [
                "etcd answers unauthenticated — read a key's value read-only "
                "(`curl -s {target}:2379/v2/keys/<key>`); etcd often stores secrets / k8s tokens."
            ]
        if "version" in kinds:
            return [
                "etcd reachable — the v2 keys API is disabled or secured; note the version only."
            ]
        return []
