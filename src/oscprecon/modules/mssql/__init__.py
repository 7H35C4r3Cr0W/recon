from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.mssql.parsers import (
    MssqlFinding,
    parse_mssql_info,
    parse_mssql_tool,
)

__all__ = [
    "MSSQL_SERVICE_NAMES",
    "MssqlFinding",
    "MssqlModule",
    "MssqlStep",
    "parse_mssql_info",
    "parse_mssql_tool",
]

MSSQL_SERVICE_NAMES = frozenset({"ms-sql-s", "mssql", "ms-sql", "ms-sql-m"})
_MSSQL_PORTS = frozenset({1433})
_DEFAULT_PORT = 1433
# ms-sql-info + ms-sql-ntlm-info are pre-login info leaks (read-only, no credential attempt). The
# single sa-empty / sa:sa default-cred checks are Tier-2 (manual_commands.yaml), never auto here.
_INFO_SCRIPTS = "ms-sql-info,ms-sql-ntlm-info"


@dataclass
class MssqlStep:
    command: Command
    tool: str = ""


class MssqlModule(Module):
    name = "mssql"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in MSSQL_SERVICE_NAMES or s.port in _MSSQL_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target) -> list[MssqlStep]:
        shell_line = f"nmap -sV -p {_DEFAULT_PORT} --script {_INFO_SCRIPTS} {target.ip}"
        return [
            MssqlStep(
                Command(
                    "mssql",
                    shell_line,
                    "Unauth banner — ms-sql-info + ntlm-info leak version/instance/AD domain "
                    "(read-only, no login).",
                    "< 30s",
                    "mssql/nmap-info.txt",
                ),
                "mssql-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for mf in parse_mssql_tool(tool, text):
                findings.append(
                    Finding(
                        service="mssql",
                        title=f"{mf.kind}: {mf.value}",
                        detail=mf.detail,
                        fields={"kind": mf.kind, "value": mf.value, "detail": mf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        kinds = {f.fields.get("kind") for f in findings}
        if "version" in kinds or "instance" in kinds:
            out.append(
                "MSSQL reachable — try a SINGLE default-cred check as Tier-2 (sa with an empty "
                "password, then sa:sa); never iterate a list. On success, enumerate read-only."
            )
        if "domain" in kinds:
            out.append(
                "NTLM leaks the AD domain — this host is domain-joined; cross-reference the domain "
                "with LDAP / SMB / Kerberos enumeration."
            )
        return out
