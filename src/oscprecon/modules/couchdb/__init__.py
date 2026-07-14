from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.couchdb.parsers import (
    CouchFinding,
    parse_couch_dbs,
    parse_couch_membership,
    parse_couch_root,
    parse_couch_tool,
)

__all__ = [
    "COUCH_SERVICE_NAMES",
    "CouchdbModule",
    "CouchFinding",
    "CouchStep",
    "parse_couch_dbs",
    "parse_couch_membership",
    "parse_couch_root",
    "parse_couch_tool",
]

COUCH_SERVICE_NAMES = frozenset({"couchdb"})
_COUCH_PORTS = frozenset({5984, 6984})
_DEFAULT_PORT = 5984
# All reads are unauthenticated HTTP GETs (read-only). If _all_dbs returns without a 401 the cluster
# is in "admin party" (no authentication) — flagged; otherwise auth-required is reported.


@dataclass
class CouchStep:
    command: Command
    tool: str = ""


class CouchdbModule(Module):
    name = "couchdb"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in COUCH_SERVICE_NAMES or s.port in _COUCH_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[CouchStep]:
        base = f"http://{target.ip}:{port or _DEFAULT_PORT}"
        return [
            CouchStep(
                Command(
                    "couchdb",
                    f"curl -s {base}/",
                    "Welcome JSON — CouchDB version + vendor (unauth read-only).",
                    "< 30s",
                    "couchdb/root.json",
                ),
                "couch-root",
            ),
            CouchStep(
                Command(
                    "couchdb",
                    f"curl -s {base}/_all_dbs",
                    "Database list — every db name if the node is unauthenticated (read-only).",
                    "< 30s",
                    "couchdb/all_dbs.json",
                ),
                "couch-dbs",
            ),
            CouchStep(
                Command(
                    "couchdb",
                    f"curl -s {base}/_membership",
                    "Cluster membership — node names (read-only).",
                    "< 30s",
                    "couchdb/membership.json",
                ),
                "couch-membership",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for cf in parse_couch_tool(tool, text):
                findings.append(
                    Finding(
                        service="couchdb",
                        title=f"{cf.kind}: {cf.value}",
                        detail=cf.detail,
                        fields={"kind": cf.kind, "value": cf.value, "detail": cf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind"): f.fields.get("value", "") for f in findings}
        if kinds.get("access") == "unauth" or "database" in kinds:
            return [
                "CouchDB answers unauthenticated (admin party) — read a database's docs with "
                "`curl -s {target}:5984/<db>/_all_docs?limit=5` (bounded, read-only)."
            ]
        if kinds.get("access") == "auth-required":
            return ["CouchDB requires auth — note the version; no login is attempted."]
        return []
