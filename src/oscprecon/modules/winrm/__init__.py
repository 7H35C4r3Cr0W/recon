from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.winrm.parsers import (
    WinrmFinding,
    parse_winrm_http,
    parse_winrm_nxc,
    parse_winrm_tool,
)

__all__ = [
    "WINRM_SERVICE_NAMES",
    "WinrmFinding",
    "WinrmModule",
    "WinrmStep",
    "parse_winrm_http",
    "parse_winrm_nxc",
    "parse_winrm_tool",
]

WINRM_SERVICE_NAMES = frozenset({"wsman", "wsmans", "winrm"})
_WINRM_PORTS = frozenset({5985, 5986})
_DEFAULT_PORT = 5985
# netexec's banner line leaks host/domain/OS without a credential; a GET on /wsman returns 405 on a
# live WinRM endpoint. No login is attempted — credentialed WinRM is a shell target (Spray mode).


@dataclass
class WinrmStep:
    command: Command
    tool: str = ""


class WinrmModule(Module):
    name = "winrm"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in WINRM_SERVICE_NAMES or s.port in _WINRM_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target, port: int = 0) -> list[WinrmStep]:
        host = target.ip
        port_n = port or _DEFAULT_PORT
        # 5986 is WinRM-over-HTTPS (self-signed in labs) — GET it over https -k, not plain http.
        scheme = "https" if port_n == 5986 else "http"
        insecure = " -k" if scheme == "https" else ""
        return [
            WinrmStep(
                Command(
                    "winrm",
                    f"netexec winrm {host}",
                    "netexec WinRM banner — host, domain, OS build (no credential attempt).",
                    "< 30s",
                    "winrm/netexec.txt",
                ),
                "winrm-nxc",
            ),
            WinrmStep(
                Command(
                    "winrm",
                    f"curl -s -i{insecure} {scheme}://{host}:{port_n}/wsman",
                    "GET /wsman — a 405 confirms a live WinRM endpoint; Server header (read-only).",
                    "< 30s",
                    "winrm/wsman.txt",
                ),
                "winrm-http",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for wf in parse_winrm_tool(tool, text):
                findings.append(
                    Finding(
                        service="winrm",
                        title=f"{wf.kind}: {wf.value}",
                        detail=wf.detail,
                        fields={"kind": wf.kind, "value": wf.value, "detail": wf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        kinds = {f.fields.get("kind") for f in findings}
        out: list[str] = []
        if "domain" in kinds:
            out.append(
                "WinRM leaks the AD domain — this host is domain-joined; cross-reference it "
                "with LDAP / SMB / Kerberos enumeration."
            )
        if "endpoint" in kinds or "host" in kinds:
            out.append(
                "WinRM is a shell target once you hold valid credentials — evaluate it in opt-in "
                "Spray mode (off by default); no login is attempted during recon."
            )
        return out
