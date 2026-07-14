from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.msrpc.parsers import (
    MsrpcFinding,
    parse_msrpc_nmap,
    parse_msrpc_tool,
    parse_rpcdump,
)

__all__ = [
    "MSRPC_SERVICE_NAMES",
    "MsrpcFinding",
    "MsrpcModule",
    "MsrpcStep",
    "parse_msrpc_nmap",
    "parse_msrpc_tool",
    "parse_rpcdump",
]

MSRPC_SERVICE_NAMES = frozenset({"msrpc", "epmap", "ms-rpc"})
_MSRPC_PORTS = frozenset({135})
_DEFAULT_PORT = 135
# impacket-rpcdump queries the RPC endpoint mapper unauthenticated (read-only): it lists interface
# UUIDs, named pipes and dynamic-port bindings. WMI/DCOM command exec runs over the dynamic ports
# and is out of scope — only the endpoint enumeration is wrapped here.


@dataclass
class MsrpcStep:
    command: Command
    tool: str = ""


class MsrpcModule(Module):
    name = "msrpc"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in MSRPC_SERVICE_NAMES or s.port in _MSRPC_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[MsrpcStep]:
        host = target.ip
        return [
            MsrpcStep(
                Command(
                    "msrpc",
                    f"impacket-rpcdump {host}",
                    "Dump the RPC endpoint mapper — interface UUIDs, named pipes, dynamic ports "
                    "(unauth read-only).",
                    "< 30s",
                    "msrpc/rpcdump.txt",
                ),
                "msrpc-rpcdump",
            ),
            MsrpcStep(
                Command(
                    "msrpc",
                    f"nmap -sV -p {port or _DEFAULT_PORT} --script msrpc-enum {host}",
                    "nmap msrpc-enum — RPC service info (read-only).",
                    "< 30s",
                    "msrpc/nmap-enum.txt",
                ),
                "msrpc-nmap",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        seen: set[tuple[str, str]] = set()
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for mf in parse_msrpc_tool(tool, text):
                if (mf.kind, mf.value) in seen:
                    continue
                seen.add((mf.kind, mf.value))
                findings.append(
                    Finding(
                        service="msrpc",
                        title=f"{mf.kind}: {mf.value}",
                        detail=mf.detail,
                        fields={"kind": mf.kind, "value": mf.value, "detail": mf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind") for f in findings}
        if "access" in kinds or "pipe" in kinds:
            return [
                "The RPC endpoint mapper answers unauthenticated — the named pipes/interfaces map "
                "to services (SAMR/LSARPC). Enumerate users via an SMB null session or rpcclient."
            ]
        return []
