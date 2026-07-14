from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.telnet.parsers import (
    TelnetFinding,
    parse_telnet_info,
    parse_telnet_tool,
)

__all__ = [
    "TELNET_SERVICE_NAMES",
    "TelnetFinding",
    "TelnetModule",
    "TelnetStep",
    "parse_telnet_info",
    "parse_telnet_tool",
]

TELNET_SERVICE_NAMES = frozenset({"telnet"})
_TELNET_PORTS = frozenset({23})
_DEFAULT_PORT = 23
# telnet-encryption reports whether the server offers transport encryption; telnet-ntlm-info leaks
# the AD domain/host from a Windows telnet NTLM challenge. Both are pre-auth reads — no login.
_INFO_SCRIPTS = "telnet-encryption,telnet-ntlm-info"


@dataclass
class TelnetStep:
    command: Command
    tool: str = ""


class TelnetModule(Module):
    name = "telnet"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in TELNET_SERVICE_NAMES or s.port in _TELNET_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[TelnetStep]:
        shell_line = f"nmap -sV -p {port or _DEFAULT_PORT} --script {_INFO_SCRIPTS} {target.ip}"
        return [
            TelnetStep(
                Command(
                    "telnet",
                    shell_line,
                    "Telnet read — encryption support + NTLM info (AD domain/host on Windows "
                    "telnet); read-only, no login.",
                    "< 30s",
                    "telnet/nmap-info.txt",
                ),
                "telnet-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for tf in parse_telnet_tool(tool, text):
                findings.append(
                    Finding(
                        service="telnet",
                        title=f"{tf.kind}: {tf.value}",
                        detail=tf.detail,
                        fields={"kind": tf.kind, "value": tf.value, "detail": tf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind"): f.fields.get("value", "") for f in findings}
        out: list[str] = []
        if kinds.get("encryption") == "not-supported":
            out.append(
                "Telnet offers no transport encryption — any login crosses the wire in cleartext. "
                "Note it; credential testing is Spray-mode only (off by default)."
            )
        if "domain" in kinds:
            out.append(
                "Telnet NTLM leaks the AD domain — pivot the domain into LDAP / SMB / Kerberos "
                "enumeration."
            )
        return out
