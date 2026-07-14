from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.x11.parsers import (
    X11Finding,
    parse_x11_access,
    parse_x11_tool,
)

__all__ = [
    "X11_SERVICE_NAMES",
    "X11Finding",
    "X11Module",
    "X11Step",
    "parse_x11_access",
    "parse_x11_tool",
]

X11_SERVICE_NAMES = frozenset({"x11", "x11-http"})
_X11_PORTS = frozenset(range(6000, 6010))
_DEFAULT_PORT = 6000
# x11-access tests whether the X server grants an unauthenticated client access to the display.
_INFO_SCRIPTS = "x11-access"


@dataclass
class X11Step:
    command: Command
    tool: str = ""


class X11Module(Module):
    name = "x11"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in X11_SERVICE_NAMES or s.port in _X11_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[X11Step]:
        shell_line = f"nmap -sV -p {port or _DEFAULT_PORT} --script {_INFO_SCRIPTS} {target.ip}"
        return [
            X11Step(
                Command(
                    "x11",
                    shell_line,
                    "x11-access — tests whether the X server grants an unauthenticated client "
                    "access to the display (read-only; no screen capture).",
                    "< 30s",
                    "x11/nmap-access.txt",
                ),
                "x11-access",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for xf in parse_x11_tool(tool, text):
                findings.append(
                    Finding(
                        service="x11",
                        title=f"{xf.kind}: {xf.value}",
                        detail=xf.detail,
                        fields={"kind": xf.kind, "value": xf.value, "detail": xf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind"): f.fields.get("value", "") for f in findings}
        if kinds.get("access") == "anonymous":
            return [
                "X server grants unauthenticated access — the display is open. Screen/keystroke "
                "capture (xwd / xdotool) is outside this recon tool; note the open display."
            ]
        return []
