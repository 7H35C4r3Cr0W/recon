from __future__ import annotations

from dataclasses import dataclass

from oscprecon.models import Command, Credential, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.smb.parsers import (
    SmbFinding,
    netexec_auth_ok,
    parse_smb_tool,
    readable_shares,
)

__all__ = [
    "SMB_SERVICE_NAMES",
    "SmbFinding",
    "SmbModule",
    "SmbStep",
    "anon_credential",
    "backslash_unc",
    "escaped_unc",
    "forward_unc",
    "netexec_auth_ok",
    "parse_smb_tool",
    "readable_shares",
]

SMB_SERVICE_NAMES = frozenset({"microsoft-ds", "netbios-ssn", "smb", "microsoft-ds?"})
_SMB_PORTS = frozenset({139, 445})


@dataclass
class SmbStep:
    command: Command
    tool: str = ""  # parser key for the output, or "" when the output is not parsed


def forward_unc(target: str, share: str = "") -> str:
    return f"//{target}/{share}"


def backslash_unc(target: str, share: str = "") -> str:
    return f"\\\\{target}\\{share}"


def escaped_unc(target: str, share: str = "") -> str:
    return f"\\\\\\\\{target}\\\\{share}"


def anon_credential(target: Target, method: str) -> Credential:
    username = "guest" if method == "guest" else "anonymous"
    return Credential(
        username=username,
        secret="",
        secret_type="password",
        domain=target.hostname or "",
        source="smb-anon-enum",
        notes=f"SMB {method} session succeeded",
    )


def _method_user(method: str) -> str:
    return "guest" if method == "guest" else ""


class SmbModule(Module):
    name = "smb"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in SMB_SERVICE_NAMES or s.port in _SMB_PORTS
            for s in scan_results.services
        )

    def banner_steps(self, target: Target) -> list[SmbStep]:
        host = target.ip
        return [
            SmbStep(
                Command(
                    "smb",
                    "nmap --script smb-os-discovery,smb-protocols,smb-security-mode,"
                    f"smb2-security-mode -p 139,445 {host}",
                    "OS / protocol / signing discovery via SMB NSE scripts.",
                    "< 1 min",
                    "smb/nmap-smb.txt",
                )
            ),
            SmbStep(
                Command(
                    "smb",
                    f"netexec smb {host}",
                    "SMB banner + signing.",
                    "< 30s",
                    "smb/netexec-banner.txt",
                ),
                "netexec-shares",
            ),
        ]

    def null_session_steps(self, target: Target) -> list[SmbStep]:
        host = target.ip
        base = "smb/null-session"
        return [
            SmbStep(
                Command(
                    "smb",
                    f"smbclient -L //{host}/ -N",
                    "List shares via null session.",
                    "< 30s",
                    f"{base}/smbclient-L.txt",
                ),
                "smbclient-shares",
            ),
            SmbStep(
                Command(
                    "smb",
                    f"netexec smb {host} -u '' -p '' --shares",
                    "Shares + permissions via null session.",
                    "< 30s",
                    f"{base}/netexec-shares.txt",
                ),
                "netexec-shares",
            ),
            SmbStep(
                Command(
                    "smb",
                    f"enum4linux-ng -A {host}",
                    "Broad anonymous enumeration.",
                    "1-5 min",
                    f"{base}/enum4linux-ng.txt",
                ),
            ),
        ]

    def guest_steps(self, target: Target) -> list[SmbStep]:
        host = target.ip
        base = "smb/guest"
        return [
            SmbStep(
                Command(
                    "smb",
                    f"netexec smb {host} -u 'guest' -p '' --shares",
                    "Shares + permissions via guest.",
                    "< 30s",
                    f"{base}/netexec-shares.txt",
                ),
                "netexec-shares",
            ),
            SmbStep(
                Command(
                    "smb",
                    f"smbclient -L //{host}/ -U 'guest%'",
                    "List shares as guest.",
                    "< 30s",
                    f"{base}/smbclient-L.txt",
                ),
                "smbclient-shares",
            ),
        ]

    def followup_steps(self, target: Target, method: str) -> list[SmbStep]:
        host = target.ip
        user = _method_user(method)
        return [
            SmbStep(
                Command(
                    "smb",
                    f"netexec smb {host} -u '{user}' -p '' --users",
                    "Enumerate domain users.",
                    "< 30s",
                    "smb/users.txt",
                ),
                "netexec-users",
            ),
            SmbStep(
                Command(
                    "smb",
                    f"netexec smb {host} -u '{user}' -p '' --pass-pol",
                    "Password policy.",
                    "< 30s",
                    "smb/pass-pol.txt",
                ),
                "netexec-passpol",
            ),
            SmbStep(
                Command(
                    "smb",
                    f"netexec smb {host} -u '{user}' -p '' --rid-brute 10000",
                    "RID cycling (recon, not a credential brute).",
                    "1-5 min",
                    "smb/rid-brute.txt",
                ),
                "netexec-ridbrute",
            ),
            SmbStep(
                Command(
                    "smb",
                    f"rpcclient -U '' -N {host} -c 'enumdomusers'",
                    "RPC null-session user enumeration.",
                    "< 30s",
                    "smb/rpcclient-enumdomusers.txt",
                ),
                "rpcclient-users",
            ),
        ]

    def share_steps(self, target: Target, share: str, method: str) -> list[SmbStep]:
        host = target.ip
        auth = "-U 'guest%'" if method == "guest" else "-N"
        safe = share.replace("$", "").replace("/", "-") or "share"
        return [
            SmbStep(
                Command(
                    "smb",
                    f"smbclient //{host}/{share} {auth} -c 'ls'",
                    f"Root listing of share {share}.",
                    "< 30s",
                    f"smb/shares/{safe}-ls.txt",
                ),
            )
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        steps = (
            self.banner_steps(target) + self.null_session_steps(target) + self.guest_steps(target)
        )
        return [step.command for step in steps]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for sf in parse_smb_tool(tool, text):
                findings.append(
                    Finding(
                        service="smb",
                        title=f"{sf.kind}: {sf.value}",
                        detail=sf.detail,
                        fields={"kind": sf.kind, "value": sf.value, "detail": sf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        for finding in findings:
            if (
                finding.fields.get("kind") == "signing"
                and finding.fields.get("value") == "disabled"
            ):
                out.append(
                    "SMB signing disabled — relay candidate. Confirm scope before attempting."
                )
                break
        return out
