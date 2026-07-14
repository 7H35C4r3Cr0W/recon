from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.openvpn.parsers import (
    OpenvpnFinding,
    parse_openvpn_info,
    parse_openvpn_tool,
)

__all__ = [
    "OPENVPN_SERVICE_NAMES",
    "OpenvpnFinding",
    "OpenvpnModule",
    "OpenvpnStep",
    "parse_openvpn_info",
    "parse_openvpn_tool",
]

OPENVPN_SERVICE_NAMES = frozenset({"openvpn"})
_OPENVPN_PORTS = frozenset({1194})
_DEFAULT_PORT = 1194
# OpenVPN with tls-auth/HMAC does not answer unauthenticated probes, so recon is limited to a
# version scan confirming the service + transport. Interacting needs a client .ovpn (CA + cert).


@dataclass
class OpenvpnStep:
    command: Command
    tool: str = ""


class OpenvpnModule(Module):
    name = "openvpn"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in OPENVPN_SERVICE_NAMES or s.port in _OPENVPN_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[OpenvpnStep]:
        # -sU because 1194 defaults to UDP; -sV so nmap's openvpn probe confirms the service.
        shell_line = f"nmap -sV -sU -p {port or _DEFAULT_PORT} {target.ip}"
        return [
            OpenvpnStep(
                Command(
                    "openvpn",
                    shell_line,
                    "Version scan — confirm the OpenVPN service and its transport (UDP/TCP); "
                    "read-only (OpenVPN rejects unauthenticated probes).",
                    "< 1 min",
                    "openvpn/nmap-info.txt",
                ),
                "openvpn-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for of in parse_openvpn_tool(tool, text):
                findings.append(
                    Finding(
                        service="openvpn",
                        title=f"{of.kind}: {of.value}",
                        detail=of.detail,
                        fields={"kind": of.kind, "value": of.value, "detail": of.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind"): f.fields.get("value", "") for f in findings}
        if "service" in kinds:
            transport = kinds.get("transport", "udp")
            return [
                f"OpenVPN confirmed on {transport} — interacting needs a client .ovpn config "
                "(CA + certificate/creds). No unauthenticated enumeration is possible here."
            ]
        return []
