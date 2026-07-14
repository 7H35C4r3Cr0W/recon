from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.finger.parsers import (
    FingerFinding,
    parse_finger_tool,
    parse_finger_users,
)

__all__ = [
    "FINGER_SERVICE_NAMES",
    "FingerFinding",
    "FingerModule",
    "FingerStep",
    "parse_finger_tool",
    "parse_finger_users",
]

FINGER_SERVICE_NAMES = frozenset({"finger"})
_FINGER_PORTS = frozenset({79})
_DEFAULT_PORT = 79


@dataclass
class FingerStep:
    command: Command
    tool: str = ""


class FingerModule(Module):
    name = "finger"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in FINGER_SERVICE_NAMES or s.port in _FINGER_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[FingerStep]:
        host = target.ip
        port_n = port or _DEFAULT_PORT
        return [
            FingerStep(
                Command(
                    "finger",
                    f"finger @{host}",
                    "List currently logged-in users via the finger daemon (read-only).",
                    "< 30s",
                    "finger/finger-at.txt",
                ),
                "finger-query",
            ),
            FingerStep(
                Command(
                    "finger",
                    f"nmap -sV -p {port_n} --script finger {host}",
                    "nmap finger NSE — banner + default finger response (read-only).",
                    "< 30s",
                    "finger/nmap-finger.txt",
                ),
                "finger-nse",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        # dedupe usernames across the finger-query and finger-nse outputs (they overlap heavily).
        seen: set[str] = set()
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for ff in parse_finger_tool(tool, text):
                if ff.kind == "user" and ff.value in seen:
                    continue
                if ff.kind == "user":
                    seen.add(ff.value)
                findings.append(
                    Finding(
                        service="finger",
                        title=f"{ff.kind}: {ff.value}",
                        detail=ff.detail,
                        fields={"kind": ff.kind, "value": ff.value, "detail": ff.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        users = sorted(
            f.fields.get("value", "") for f in findings if f.fields.get("kind") == "user"
        )
        if users:
            shown = ", ".join(users[:6]) + (" …" if len(users) > 6 else "")
            return [
                f"Finger disclosed {len(users)} system username(s) ({shown}) — build a target user "
                "list for later authorized SSH / SMB / Kerberos enumeration (no guessing here)."
            ]
        return []
