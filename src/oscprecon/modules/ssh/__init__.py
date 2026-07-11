from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.ssh.parsers import SshFinding, parse_nmap_ssh, parse_ssh_tool

__all__ = [
    "SSH_SERVICE_NAMES",
    "SshFinding",
    "SshModule",
    "SshStep",
    "parse_nmap_ssh",
    "parse_ssh_tool",
]

SSH_SERVICE_NAMES = frozenset({"ssh"})
_SSH_PORTS = frozenset({22})


@dataclass
class SshStep:
    command: Command
    tool: str = ""  # parser key for the output, or "" when the output is not parsed


class SshModule(Module):
    name = "ssh"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in SSH_SERVICE_NAMES or s.port in _SSH_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 22) -> list[SshStep]:
        host = target.ip
        return [
            SshStep(
                Command(
                    "ssh",
                    f"nmap -sV --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey "
                    f"-p {port} {host}",
                    "Banner, algorithms, host keys, and offered auth methods (all recon).",
                    "< 1 min",
                    "ssh/nmap-ssh.txt",
                ),
                "nmap-ssh",
            )
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for sf in parse_ssh_tool(tool, text):
                findings.append(
                    Finding(
                        service="ssh",
                        title=f"{sf.kind}: {sf.value}",
                        detail=sf.detail,
                        fields={"kind": sf.kind, "value": sf.value, "detail": sf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        if any(
            f.fields.get("kind") == "auth" and f.fields.get("value") == "password" for f in findings
        ):
            out.append(
                "Password authentication enabled — single default-cred checks are Tier-2 "
                "(one manual attempt each; never a list or brute force)."
            )
        weak = [f.fields.get("value", "") for f in findings if f.fields.get("kind") == "algo-weak"]
        if weak:
            out.append(
                f"Weak SSH algorithms offered ({', '.join(sorted(set(weak)))}) — "
                "note for the report; not exploitable on its own."
            )
        banners = [f.fields.get("value", "") for f in findings if f.fields.get("kind") == "banner"]
        if banners:
            out.append(
                f"SSH banner '{banners[0]}' — look the version up in the Exploit-DB pane (recon)."
            )
        return out
