from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.oracle.parsers import (
    OracleFinding,
    parse_oracle_info,
    parse_oracle_tool,
)

__all__ = [
    "ORACLE_SERVICE_NAMES",
    "OracleFinding",
    "OracleModule",
    "OracleStep",
    "parse_oracle_info",
    "parse_oracle_tool",
]

ORACLE_SERVICE_NAMES = frozenset({"oracle-tns", "oracle", "tns"})
_ORACLE_PORTS = frozenset({1521, 1522, 1526})
_DEFAULT_PORT = 1521
# oracle-tns-version reads the TNS listener version pre-auth. SID enumeration (oracle-sid-brute) is
# list-based, so it is a Tier-2 manual follow-up, not run here. No login is attempted.
_INFO_SCRIPTS = "oracle-tns-version"


@dataclass
class OracleStep:
    command: Command
    tool: str = ""


class OracleModule(Module):
    name = "oracle"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in ORACLE_SERVICE_NAMES or s.port in _ORACLE_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[OracleStep]:
        shell_line = f"nmap -sV -p {port or _DEFAULT_PORT} --script {_INFO_SCRIPTS} {target.ip}"
        return [
            OracleStep(
                Command(
                    "oracle",
                    shell_line,
                    "Oracle TNS listener version (read-only, no login). A valid SID is required "
                    "before any auth — SID enumeration is a Tier-2 follow-up.",
                    "< 30s",
                    "oracle/nmap-info.txt",
                ),
                "oracle-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for of in parse_oracle_tool(tool, text):
                findings.append(
                    Finding(
                        service="oracle",
                        title=f"{of.kind}: {of.value}",
                        detail=of.detail,
                        fields={"kind": of.kind, "value": of.value, "detail": of.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind") for f in findings}
        if "version" in kinds:
            return [
                "Oracle TNS listener reachable — a valid SID is needed before any auth. Enumerate "
                "SIDs as a Tier-2 follow-up (oracle-sid-brute); odat/tnscmd10g are outside this."
            ]
        return []
