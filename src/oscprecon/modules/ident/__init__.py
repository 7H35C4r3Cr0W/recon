from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.ident.parsers import (
    IdentFinding,
    parse_ident_info,
    parse_ident_tool,
)

__all__ = [
    "IDENT_SERVICE_NAMES",
    "IdentFinding",
    "IdentModule",
    "IdentStep",
    "parse_ident_info",
    "parse_ident_tool",
]

IDENT_SERVICE_NAMES = frozenset({"ident", "auth", "identd"})
_IDENT_PORTS = frozenset({113})
_DEFAULT_PORT = 113
# auth-owners queries the ident daemon (113) for the local user that owns each open port. Scanning a
# small common-port set alongside 113 maps service ports -> usernames read-only (no login).
_COMMON_PORTS = "21,22,25,80,110,139,143,443,445,3306,8080"


@dataclass
class IdentStep:
    command: Command
    tool: str = ""


class IdentModule(Module):
    name = "ident"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in IDENT_SERVICE_NAMES or s.port in _IDENT_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[IdentStep]:
        ports = f"{port or _DEFAULT_PORT},{_COMMON_PORTS}"
        shell_line = f"nmap -sV -p {ports} --script auth-owners {target.ip}"
        return [
            IdentStep(
                Command(
                    "ident",
                    shell_line,
                    "auth-owners — ask the ident daemon which local user owns each open port "
                    "(maps services to usernames; read-only).",
                    "< 1 min",
                    "ident/nmap-info.txt",
                ),
                "ident-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        seen: set[tuple[str, str]] = set()
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for idf in parse_ident_tool(tool, text):
                if (idf.kind, idf.value) in seen:
                    continue
                seen.add((idf.kind, idf.value))
                findings.append(
                    Finding(
                        service="ident",
                        title=f"{idf.kind}: {idf.value}",
                        detail=idf.detail,
                        fields={"kind": idf.kind, "value": idf.value, "detail": idf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        users = sorted(
            f.fields.get("value", "") for f in findings if f.fields.get("kind") == "user"
        )
        if users:
            shown = ", ".join(users[:6]) + (" …" if len(users) > 6 else "")
            return [
                f"ident disclosed the service owner(s) ({shown}) — a service running as a named "
                "user is a target account for later authorized enumeration (no guessing here)."
            ]
        return []
