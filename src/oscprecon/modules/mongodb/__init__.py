from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.mongodb.parsers import (
    MongoFinding,
    parse_mongo_collections,
    parse_mongo_databases,
    parse_mongo_nmap,
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
    "parse_mongo_nmap",
    "parse_mongo_tool",
    "parse_mongo_version",
]

MONGODB_SERVICE_NAMES = frozenset({"mongodb", "mongod"})
_MONGODB_PORTS = frozenset({27017, 27018, 27019})
_DEFAULT_PORT = 27017


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

    def recon_steps(self, target: Target, port: int = _DEFAULT_PORT) -> list[MongoDbStep]:
        port = port or _DEFAULT_PORT
        # why: Tier-1 uses nmap NSE, not mongosh. mongosh isn't a stock Kali tool, and modern
        # mongosh version-refuses the old MongoDB (<= 3.6, wire v6) these boxes run — the wall the
        # write-up hits. nmap needs no client and speaks the wire protocol directly, so it lists the
        # databases anonymously every time (read-only). Deeper mongosh enum (collections, document
        # samples, serverStatus) stays in the Tier-2 manual follow-ups.
        return [
            MongoDbStep(
                Command(
                    "mongodb",
                    f"nmap -p {port} --script mongodb-info,mongodb-databases {target.ip}",
                    "Unauth server info + database list via nmap NSE — no client needed; a locked "
                    "server returns an auth error instead of the DB list (read-only).",
                    "< 30s",
                    "mongodb/nmap-info.txt",
                ),
                "mongodb-nmap",
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
