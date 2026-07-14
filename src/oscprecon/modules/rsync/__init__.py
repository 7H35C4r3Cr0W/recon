from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.rsync.parsers import (
    RsyncFinding,
    parse_rsync_modules,
    parse_rsync_tool,
)

__all__ = [
    "RSYNC_SERVICE_NAMES",
    "RsyncFinding",
    "RsyncModule",
    "RsyncStep",
    "parse_rsync_modules",
    "parse_rsync_tool",
]

RSYNC_SERVICE_NAMES = frozenset({"rsync"})
_RSYNC_PORTS = frozenset({873})
_DEFAULT_PORT = 873
# Listing modules (and, per-module, their contents) is read-only enumeration. Downloading files or
# authenticating to a password-protected module is an explicit Tier-2 follow-up, never auto here.


@dataclass
class RsyncStep:
    command: Command
    tool: str = ""


class RsyncModule(Module):
    name = "rsync"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in RSYNC_SERVICE_NAMES or s.port in _RSYNC_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[RsyncStep]:
        host = target.ip
        port_n = port or _DEFAULT_PORT
        return [
            RsyncStep(
                Command(
                    "rsync",
                    f"rsync --list-only --contimeout=10 rsync://{host}:{port_n}/",
                    "List exposed rsync modules (read-only; no download).",
                    "< 30s",
                    "rsync/modules.txt",
                ),
                "rsync-modules",
            ),
            RsyncStep(
                Command(
                    "rsync",
                    f"nmap -sV -p {port_n} --script rsync-list-modules {host}",
                    "nmap rsync-list-modules — modules via NSE (read-only).",
                    "< 30s",
                    "rsync/nmap-modules.txt",
                ),
                "rsync-nmap",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        # both steps enumerate the same modules — dedupe by (kind, value) across them
        seen: set[tuple[str, str]] = set()
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for rf in parse_rsync_tool(tool, text):
                if (rf.kind, rf.value) in seen:
                    continue
                seen.add((rf.kind, rf.value))
                findings.append(
                    Finding(
                        service="rsync",
                        title=f"{rf.kind}: {rf.value}",
                        detail=rf.detail,
                        fields={"kind": rf.kind, "value": rf.value, "detail": rf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        modules = [f.fields.get("value", "") for f in findings if f.fields.get("kind") == "module"]
        if modules:
            first = modules[0]
            return [
                f"{len(modules)} rsync module(s) exposed — list a module's contents read-only "
                f"(`rsync --list-only rsync://{{target}}/{first}/`); auth-protected ones stop here."
            ]
        return []
