from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.upnp.parsers import (
    UpnpFinding,
    parse_upnp_info,
    parse_upnp_tool,
)

__all__ = [
    "UPNP_SERVICE_NAMES",
    "UpnpFinding",
    "UpnpModule",
    "UpnpStep",
    "parse_upnp_info",
    "parse_upnp_tool",
]

UPNP_SERVICE_NAMES = frozenset({"upnp", "ssdp"})
_UPNP_PORTS = frozenset({1900})
_DEFAULT_PORT = 1900
# upnp-info reads the SSDP/UPnP device description (server banner, description URL, device details)
# read-only. UPnP is UDP, so -sU is required. Adding a port mapping is an action — never issued.
_INFO_SCRIPTS = "upnp-info"


@dataclass
class UpnpStep:
    command: Command
    tool: str = ""


class UpnpModule(Module):
    name = "upnp"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in UPNP_SERVICE_NAMES or s.port in _UPNP_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[UpnpStep]:
        shell_line = f"nmap -sU -p {port or _DEFAULT_PORT} --script {_INFO_SCRIPTS} {target.ip}"
        return [
            UpnpStep(
                Command(
                    "upnp",
                    shell_line,
                    "upnp-info — server banner, device description URL, manufacturer/model "
                    "(read-only; UDP so it may need a retry).",
                    "< 1 min",
                    "upnp/nmap-info.txt",
                ),
                "upnp-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for uf in parse_upnp_tool(tool, text):
                findings.append(
                    Finding(
                        service="upnp",
                        title=f"{uf.kind}: {uf.value}",
                        detail=uf.detail,
                        fields={"kind": uf.kind, "value": uf.value, "detail": uf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind"): f.fields.get("value", "") for f in findings}
        if "location" in kinds:
            return [
                "UPnP exposes a device description — fetch it read-only for the internal service "
                f"map (`curl -s {kinds['location']}`); adding a port mapping is out of scope."
            ]
        if "server" in kinds:
            return ["UPnP responds — note the server/device banner for reference (read-only)."]
        return []
