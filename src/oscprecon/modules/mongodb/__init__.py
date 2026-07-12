from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.mongodb.parsers import (
    MongoFinding,
    parse_mongo_collections,
    parse_mongo_databases,
    parse_mongo_tool,
    parse_mongo_version,
)

__all__ = [
    "MONGODB_SERVICE_NAMES",
    "MongoDbModule",
    "MongoDbStep",
    "MongoFinding",
    "parse_mongo_collections",
    "parse_mongo_databases",
    "parse_mongo_tool",
    "parse_mongo_version",
]

MONGODB_SERVICE_NAMES = frozenset({"mongodb", "mongod"})
_MONGODB_PORTS = frozenset({27017, 27018, 27019})
_DEFAULT_PORT = 27017

# print()-wrapped so output is identical across mongosh and the legacy `mongo` shell (which render
# objects differently). getDBNames() asserts: on auth it throws the server errmsg in both shells,
# so auth-required is always detectable. All read-only — no insert/update/drop/eval.
_VERSION_EVAL = "print(db.version())"
_DB_EVAL = "db.getMongo().getDBNames().forEach(function(n){print('DB '+n)})"
_COLL_EVAL = (
    "db.getMongo().getDBNames().forEach(function(n){"
    "db.getSiblingDB(n).getCollectionNames().forEach(function(c){print(n+'.'+c)})})"
)


@dataclass
class MongoDbStep:
    command: Command
    tool: str = ""


class MongoDbModule(Module):
    name = "mongodb"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in MONGODB_SERVICE_NAMES or s.port in _MONGODB_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target) -> list[MongoDbStep]:
        base = f"mongosh --host {target.ip} --port {_DEFAULT_PORT} --quiet"
        return [
            MongoDbStep(
                Command(
                    "mongodb",
                    f'{base} --eval "{_VERSION_EVAL}"',
                    "Unauth server version — a MongoDB that answers without creds (read-only).",
                    "< 30s",
                    "mongodb/version.txt",
                ),
                "mongodb-version",
            ),
            MongoDbStep(
                Command(
                    "mongodb",
                    f'{base} --eval "{_DB_EVAL}"',
                    "Unauth database list — a locked server throws an auth error (read-only).",
                    "< 30s",
                    "mongodb/databases.txt",
                ),
                "mongodb-databases",
            ),
            MongoDbStep(
                Command(
                    "mongodb",
                    f'{base} --eval "{_COLL_EVAL}"',
                    "Unauth per-DB collection names — maps the data namespace (read-only).",
                    "< 30s",
                    "mongodb/collections.txt",
                ),
                "mongodb-collections",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for mf in parse_mongo_tool(tool, text):
                findings.append(
                    Finding(
                        service="mongodb",
                        title=f"{mf.kind}: {mf.value}",
                        detail=mf.detail,
                        fields={"kind": mf.kind, "value": mf.value, "detail": mf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        access = {f.fields.get("value") for f in findings if f.fields.get("kind") == "access"}
        notes = {f.fields.get("value") for f in findings if f.fields.get("kind") == "note"}
        if "unauth" in access:
            out.append(
                "MongoDB answers unauthenticated — enumerate a database's collections and read a "
                "bounded document sample (getCollectionNames / find().limit()) to hunt for creds."
            )
        if "auth-required" in access:
            out.append(
                "MongoDB requires authentication — a single well-known default cred is a Tier-2 "
                "check; never iterate a username/password list."
            )
        if "wire-version-mismatch" in notes:
            out.append(
                "mongosh is newer than this MongoDB — retry with the legacy `mongo` shell "
                "(it speaks the older wire protocol these boxes use)."
            )
        return out
