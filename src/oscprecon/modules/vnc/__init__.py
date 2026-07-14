from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.vnc.parsers import (
    VncFinding,
    parse_vnc_info,
    parse_vnc_tool,
)

__all__ = [
    "VNC_SERVICE_NAMES",
    "VncFinding",
    "VncModule",
    "VncStep",
    "parse_vnc_info",
    "parse_vnc_tool",
]

VNC_SERVICE_NAMES = frozenset({"vnc", "vnc-http"})
_VNC_PORTS = frozenset(range(5900, 5907))
_DEFAULT_PORT = 5900
# vnc-info reports the RFB protocol version and offered security types; vnc-title reads the desktop
# name. Both are pre-auth reads — a "None" security type means the display is open with no password.
_INFO_SCRIPTS = "vnc-info,vnc-title"


@dataclass
class VncStep:
    command: Command
    tool: str = ""


class VncModule(Module):
    name = "vnc"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in VNC_SERVICE_NAMES or s.port in _VNC_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[VncStep]:
        shell_line = f"nmap -sV -p {port or _DEFAULT_PORT} --script {_INFO_SCRIPTS} {target.ip}"
        return [
            VncStep(
                Command(
                    "vnc",
                    shell_line,
                    "Unauth VNC read — protocol version, offered security types, desktop name. "
                    "A 'None' security type means the display is open with no password.",
                    "< 30s",
                    "vnc/nmap-info.txt",
                ),
                "vnc-info",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for vf in parse_vnc_tool(tool, text):
                findings.append(
                    Finding(
                        service="vnc",
                        title=f"{vf.kind}: {vf.value}",
                        detail=vf.detail,
                        fields={"kind": vf.kind, "value": vf.value, "detail": vf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        kinds = {f.fields.get("kind"): f.fields.get("value", "") for f in findings}
        if kinds.get("access") == "anonymous":
            out.append(
                "VNC offers the 'None' security type — the display is reachable without a "
                "password. Connect read-only with a viewer to confirm what is on screen."
            )
        elif "security" in kinds:
            out.append(
                "VNC requires authentication — password guessing is list-based (Tier-3, Spray-mode "
                "only). Note the version and offered auth types for reference."
            )
        return out
