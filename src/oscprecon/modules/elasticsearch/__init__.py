from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.elasticsearch.parsers import (
    ElasticFinding,
    parse_elastic_health,
    parse_elastic_indices,
    parse_elastic_root,
    parse_elastic_tool,
)

__all__ = [
    "ELASTIC_SERVICE_NAMES",
    "ElasticFinding",
    "ElasticsearchModule",
    "ElasticStep",
    "parse_elastic_health",
    "parse_elastic_indices",
    "parse_elastic_root",
    "parse_elastic_tool",
]

ELASTIC_SERVICE_NAMES = frozenset({"elasticsearch", "wap-wsp"})
_ELASTIC_PORTS = frozenset({9200})
_DEFAULT_PORT = 9200
# All three reads are unauthenticated HTTP GETs (read-only). A secured cluster answers 401 and the
# parser flags auth-required instead of leaking data.


@dataclass
class ElasticStep:
    command: Command
    tool: str = ""


class ElasticsearchModule(Module):
    name = "elasticsearch"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in ELASTIC_SERVICE_NAMES or s.port in _ELASTIC_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[ElasticStep]:
        base = f"http://{target.ip}:{port or _DEFAULT_PORT}"
        return [
            ElasticStep(
                Command(
                    "elasticsearch",
                    f"curl -s {base}/",
                    "Root JSON — version, cluster name, tagline (unauth read-only).",
                    "< 30s",
                    "elasticsearch/root.json",
                ),
                "es-root",
            ),
            ElasticStep(
                Command(
                    "elasticsearch",
                    f"curl -s {base}/_cat/indices?v",
                    "Index list — names + doc counts if the cluster is unauthenticated.",
                    "< 30s",
                    "elasticsearch/indices.txt",
                ),
                "es-indices",
            ),
            ElasticStep(
                Command(
                    "elasticsearch",
                    f"curl -s {base}/_cluster/health?pretty",
                    "Cluster health — status + node count (read-only).",
                    "< 30s",
                    "elasticsearch/health.json",
                ),
                "es-health",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for ef in parse_elastic_tool(tool, text):
                findings.append(
                    Finding(
                        service="elasticsearch",
                        title=f"{ef.kind}: {ef.value}",
                        detail=ef.detail,
                        fields={"kind": ef.kind, "value": ef.value, "detail": ef.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind"): f.fields.get("value", "") for f in findings}
        if kinds.get("access") == "unauth" or "index" in kinds:
            return [
                "Elasticsearch answers unauthenticated — read a specific index with "
                "`curl -s {target}:9200/<index>/_search?size=5` (bounded, read-only)."
            ]
        if kinds.get("access") == "auth-required":
            return [
                "Elasticsearch requires auth (X-Pack) — note the version; no login is attempted."
            ]
        return []
