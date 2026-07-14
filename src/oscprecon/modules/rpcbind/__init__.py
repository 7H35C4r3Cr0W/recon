from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.rpcbind.parsers import (
    RpcbindFinding,
    parse_rpcbind_tool,
    parse_rpcinfo,
)

__all__ = [
    "RPCBIND_SERVICE_NAMES",
    "RpcbindFinding",
    "RpcbindModule",
    "RpcbindStep",
    "parse_rpcbind_tool",
    "parse_rpcinfo",
]

RPCBIND_SERVICE_NAMES = frozenset({"rpcbind", "portmapper", "sunrpc"})
_RPCBIND_PORTS = frozenset({111})
_DEFAULT_PORT = 111
# rpcinfo (and nmap's rpcinfo NSE) dump the portmapper's registered RPC programs unauthenticated
# (read-only): program numbers, ports and service names (nfs, mountd, nlockmgr, ypserv, status, …).


@dataclass
class RpcbindStep:
    command: Command
    tool: str = ""


class RpcbindModule(Module):
    name = "rpcbind"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in RPCBIND_SERVICE_NAMES or s.port in _RPCBIND_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[RpcbindStep]:
        host = target.ip
        return [
            RpcbindStep(
                Command(
                    "rpcbind",
                    f"rpcinfo {host}",
                    "Dump the portmapper — registered RPC programs, ports and service names "
                    "(unauth read-only).",
                    "< 30s",
                    "rpcbind/rpcinfo.txt",
                ),
                "rpcbind-rpcinfo",
            ),
            RpcbindStep(
                Command(
                    "rpcbind",
                    f"nmap -sV -p {port or _DEFAULT_PORT} --script rpcinfo {host}",
                    "nmap rpcinfo — RPC program dump via NSE (read-only).",
                    "< 30s",
                    "rpcbind/nmap-info.txt",
                ),
                "rpcbind-nmap",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        seen: set[tuple[str, str]] = set()
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for rf in parse_rpcbind_tool(tool, text):
                if (rf.kind, rf.value) in seen:
                    continue
                seen.add((rf.kind, rf.value))
                findings.append(
                    Finding(
                        service="rpcbind",
                        title=f"{rf.kind}: {rf.value}",
                        detail=rf.detail,
                        fields={"kind": rf.kind, "value": rf.value, "detail": rf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        programs = {
            f.fields.get("value", "") for f in findings if f.fields.get("kind") == "program"
        }
        out: list[str] = []
        if {"nfs", "mountd"} & programs:
            out.append(
                "rpcbind advertises NFS (nfs/mountd) — enumerate the exports read-only "
                "(`showmount -e {target}`)."
            )
        if programs - {"portmapper", "rpcbind"}:
            out.append(
                "The portmapper answers unauthenticated — the registered RPC services are "
                "enumeration targets (nlockmgr, status, ypserv, etc.); note their dynamic ports."
            )
        return out
