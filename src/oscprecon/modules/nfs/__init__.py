from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Credential, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.nfs.parsers import (
    NfsFinding,
    is_secret_name,
    parse_nfs_tool,
    parse_nmap_nfs,
    parse_showmount,
)

__all__ = [
    "NFS_SERVICE_NAMES",
    "NfsFinding",
    "NfsModule",
    "NfsStep",
    "anon_credential",
    "is_secret_name",
    "parse_nfs_tool",
    "parse_nmap_nfs",
    "parse_showmount",
]

NFS_SERVICE_NAMES = frozenset({"nfs", "nfs_acl", "nfsd", "mountd", "rpc.mountd"})
_NFS_PORTS = frozenset({2049})


@dataclass
class NfsStep:
    command: Command
    tool: str = ""  # parser key for the output, or "" when the output is not parsed


def anon_credential(target: Target) -> Credential:
    return Credential(
        username="anonymous",
        secret="",
        secret_type="none",
        domain=target.hostname or "",
        source="nfs-anon-enum",
        notes="World-readable NFS export mountable without credentials",
    )


class NfsModule(Module):
    name = "nfs"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in NFS_SERVICE_NAMES or s.port in _NFS_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 2049) -> list[NfsStep]:
        host = target.ip
        return [
            NfsStep(
                Command(
                    "nfs",
                    f"showmount -e {host}",
                    "List NFS exports and the hosts each is shared to (read-only RPC query).",
                    "< 30s",
                    "nfs/showmount.txt",
                ),
                "showmount",
            ),
            NfsStep(
                Command(
                    "nfs",
                    f"nmap -sV --script nfs-showmount,nfs-ls,nfs-statfs -p {port} {host}",
                    "Exports, a bounded directory listing over NFS (no local mount), and fs stats.",
                    "1-5 min",
                    "nfs/nmap-nfs.txt",
                ),
                "nmap-nfs",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for nf in parse_nfs_tool(tool, text):
                findings.append(
                    Finding(
                        service="nfs",
                        title=f"{nf.kind}: {nf.value}",
                        detail=nf.detail,
                        fields={"kind": nf.kind, "value": nf.value, "detail": nf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        world = [f for f in findings if f.fields.get("kind") == "world-readable"]
        if world:
            export = world[0].fields.get("value", "the export")
            out.append(
                f"World-readable NFS export ({export}) — Tier-2: mount read-only "
                "(mount -o ro,nolock) and ls -laR; copy to a terminal, needs root, confirm first. "
                "Read only, never modify."
            )
        if any(
            f.fields.get("kind") == "access" and "writable" in f.fields.get("detail", "")
            for f in findings
        ):
            out.append(
                "An NFS export is writable — note it for the report (privilege / persistence "
                "implications, e.g. no_root_squash); do not modify during recon."
            )
        secret = [
            f.fields.get("value", "")
            for f in findings
            if f.fields.get("kind") == "file" and is_secret_name(f.fields.get("value", ""))
        ]
        if secret:
            out.append(
                f"Sensitive file exposed over NFS ({secret[0]}) — read it (read-only); "
                "SSH keys / password files often enable a foothold."
            )
        return out
