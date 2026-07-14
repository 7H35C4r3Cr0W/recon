from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.svn.parsers import (
    SvnFinding,
    parse_svn_ls,
    parse_svn_nmap,
    parse_svn_tool,
)

__all__ = [
    "SVN_SERVICE_NAMES",
    "SvnFinding",
    "SvnModule",
    "SvnStep",
    "parse_svn_ls",
    "parse_svn_nmap",
    "parse_svn_tool",
]

SVN_SERVICE_NAMES = frozenset({"svnserve", "svn", "subversion"})
_SVN_PORTS = frozenset({3690})
_DEFAULT_PORT = 3690
# `svn ls` lists the repo root anonymously; nmap svn-info reads the server version + repo UUID/rev.
# Both are read-only — checking out or committing is an explicit follow-up, never issued here.


@dataclass
class SvnStep:
    command: Command
    tool: str = ""


class SvnModule(Module):
    name = "svn"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in SVN_SERVICE_NAMES or s.port in _SVN_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[SvnStep]:
        host = target.ip
        port_n = port or _DEFAULT_PORT
        return [
            SvnStep(
                Command(
                    "svn",
                    f"svn ls svn://{host}:{port_n}/",
                    "Anonymous listing of the svnserve repo root (read-only).",
                    "< 30s",
                    "svn/ls.txt",
                ),
                "svn-ls",
            ),
            SvnStep(
                Command(
                    "svn",
                    f"nmap -sV -p {port_n} --script svn-info {host}",
                    "nmap svn-info — server version + repository UUID/revision (read-only).",
                    "< 30s",
                    "svn/nmap-info.txt",
                ),
                "svn-nmap",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        seen: set[tuple[str, str]] = set()
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for sf in parse_svn_tool(tool, text):
                if (sf.kind, sf.value) in seen:
                    continue
                seen.add((sf.kind, sf.value))
                findings.append(
                    Finding(
                        service="svn",
                        title=f"{sf.kind}: {sf.value}",
                        detail=sf.detail,
                        fields={"kind": sf.kind, "value": sf.value, "detail": sf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind") for f in findings}
        if "access" in kinds or "entry" in kinds:
            return [
                "svnserve allows anonymous reads — inspect the log/history for credentials or "
                "removed files (`svn log -v svn://{target}/`, `svn cat` a file); read-only recon."
            ]
        return []
