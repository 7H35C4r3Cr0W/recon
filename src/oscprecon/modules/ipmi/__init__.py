from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.ipmi.parsers import (
    IpmiFinding,
    parse_ipmi_info,
    parse_ipmi_tool,
)

__all__ = [
    "IPMI_SERVICE_NAMES",
    "IpmiFinding",
    "IpmiModule",
    "IpmiStep",
    "parse_ipmi_info",
    "parse_ipmi_tool",
]

IPMI_SERVICE_NAMES = frozenset({"asf-rmcp", "ipmi"})
_IPMI_PORTS = frozenset({623})
_DEFAULT_PORT = 623
# ipmi-version reads the supported IPMI/auth levels; ipmi-cipher-zero detects the cipher-zero
# auth-bypass misconfig. Both are read-only NSE checks (no cred harvesting — RAKP is excluded).
_INFO_SCRIPTS = "ipmi-version,ipmi-cipher-zero"


@dataclass
class IpmiStep:
    command: Command
    tool: str = ""


class IpmiModule(Module):
    name = "ipmi"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in IPMI_SERVICE_NAMES or s.port in _IPMI_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[IpmiStep]:
        # IPMI is UDP-only — -sU is required or nmap probes the wrong (TCP) port.
        shell_line = f"nmap -sU -p {port or _DEFAULT_PORT} --script {_INFO_SCRIPTS} {target.ip}"
        return [
            IpmiStep(
                Command(
                    "ipmi",
                    shell_line,
                    "IPMI read — ipmi-version (IPMI/auth levels) + ipmi-cipher-zero (auth-bypass "
                    "misconfig detection). Read-only; UDP, so it may need a retry.",
                    "< 1 min",
                    "ipmi/nmap-info.txt",
                ),
                "ipmi-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for f in parse_ipmi_tool(tool, text):
                findings.append(
                    Finding(
                        service="ipmi",
                        title=f"{f.kind}: {f.value}",
                        detail=f.detail,
                        fields={"kind": f.kind, "value": f.value, "detail": f.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        kinds = {f.fields.get("kind"): f.fields.get("value", "") for f in findings}
        if kinds.get("cipher-zero") == "enabled":
            out.append(
                "IPMI Cipher Zero is enabled — authentication is bypassable (any password works). "
                "Note it as a critical exposure; hash-retrieval / login is beyond this recon tool."
            )
        elif "version" in kinds:
            out.append(
                "IPMI reachable — note the version/auth levels. The IPMI 2.0 RAKP hash retrieval "
                "is credential harvesting and is out of scope for this recon tool."
            )
        return out
