from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.postgresql.parsers import (
    DEFAULT_PORT,
    PostgresqlFinding,
    parse_postgresql_info,
    parse_postgresql_tool,
)

__all__ = [
    "POSTGRESQL_SERVICE_NAMES",
    "PostgresqlFinding",
    "PostgresqlModule",
    "PostgresqlStep",
    "parse_postgresql_info",
    "parse_postgresql_tool",
]

# nmap emits SERVICE=postgresql (never bare "postgres"); pgbouncer is a distinct service.
POSTGRESQL_SERVICE_NAMES = frozenset({"postgresql"})
_POSTGRESQL_PORTS = frozenset({DEFAULT_PORT})
# There is no unauth PostgreSQL info NSE (pgsql-brute is forbidden), so Tier-1 is credential-free
# `nmap -sV` version detection only. Default-cred + authenticated enum are Tier-2 (manual_commands).


@dataclass
class PostgresqlStep:
    command: Command
    tool: str = ""


class PostgresqlModule(Module):
    name = "postgresql"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in POSTGRESQL_SERVICE_NAMES or s.port in _POSTGRESQL_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[PostgresqlStep]:
        # honour the discovered port (never fall back to 5432 when found elsewhere)
        p = port or DEFAULT_PORT
        shell_line = f"nmap -sV -p {p} {target.ip}"
        return [
            PostgresqlStep(
                Command(
                    "postgresql",
                    shell_line,
                    "Unauth banner — nmap -sV version detection only (no pgsql-info NSE exists; "
                    "pgsql-brute is forbidden). No credential attempt.",
                    "< 30s",
                    f"postgresql/nmap-sv-{p}.txt",
                ),
                "postgresql-sv",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        port = ports[0].number if ports else 0
        return [step.command for step in self.recon_steps(target, port)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for pf in parse_postgresql_tool(tool, text):
                findings.append(
                    Finding(
                        service="postgresql",
                        title=f"{pf.kind}: {pf.value}",
                        detail=pf.detail,
                        fields={"kind": pf.kind, "value": pf.value, "detail": pf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        kinds = {f.fields.get("kind") for f in findings}
        if "service" in kinds or "version" in kinds:
            out.append(
                "PostgreSQL reachable — try a SINGLE default-cred check as Tier-2 (postgres with "
                "an empty password, then postgres:postgres); never iterate a list. On success, "
                "enumerate databases/roles read-only."
            )
        if "version" in kinds:
            out.append(
                "Note the exact PostgreSQL version and search Exploit-DB for it (display-only)."
            )
        return out
