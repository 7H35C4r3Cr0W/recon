from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.mysql.parsers import (
    MysqlFinding,
    parse_mysql_info,
    parse_mysql_tool,
)

__all__ = [
    "MYSQL_SERVICE_NAMES",
    "MysqlFinding",
    "MysqlModule",
    "MysqlStep",
    "parse_mysql_info",
    "parse_mysql_tool",
]

# nmap reports MariaDB hosts as service `mysql` (MariaDB shows only in the product/version text), so
# `mysql` + port 3306 cover every real case.
MYSQL_SERVICE_NAMES = frozenset({"mysql"})
_MYSQL_PORTS = frozenset({3306})
_DEFAULT_PORT = 3306
# mysql-info is an unauth pre-login handshake leak (read-only, no credential attempt). The single
# root-empty / root:root default-cred checks are Tier-2 (manual_commands.yaml), never auto here.
_INFO_SCRIPT = "mysql-info"


@dataclass
class MysqlStep:
    command: Command
    tool: str = ""


class MysqlModule(Module):
    name = "mysql"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in MYSQL_SERVICE_NAMES or s.port in _MYSQL_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[MysqlStep]:
        shell_line = f"nmap -sV -p {port or _DEFAULT_PORT} --script {_INFO_SCRIPT} {target.ip}"
        return [
            MysqlStep(
                Command(
                    "mysql",
                    shell_line,
                    "Unauth banner — mysql-info leaks protocol/version/capabilities/auth-plugin "
                    "from the pre-login handshake (read-only, no login).",
                    "< 30s",
                    "mysql/nmap-info.txt",
                ),
                "mysql-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for mf in parse_mysql_tool(tool, text):
                findings.append(
                    Finding(
                        service="mysql",
                        title=f"{mf.kind}: {mf.value}",
                        detail=mf.detail,
                        fields={"kind": mf.kind, "value": mf.value, "detail": mf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        kinds = {f.fields.get("kind") for f in findings}
        if "version" in kinds:
            out.append(
                "MySQL reachable — try a SINGLE default-cred check as Tier-2 (root with an empty "
                "password, then root:root); never iterate a list. On success, enumerate read-only."
            )
            out.append(
                "Note the exact MySQL version and search Exploit-DB for it (display-only lookup)."
            )
        return out
