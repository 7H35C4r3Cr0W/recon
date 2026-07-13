from __future__ import annotations

import hashlib
import re
import shlex
from dataclasses import dataclass

from oscprecon.models import Command, Credential, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.peek import PEEK_MAX_FILES
from oscprecon.modules.peek import is_peekable as _peek_is_peekable
from oscprecon.modules.peek import peek_snippet as peek_snippet  # re-export
from oscprecon.modules.smb.parsers import (
    SmbEntry,
    SmbFinding,
    netexec_auth_ok,
    parse_smb_tool,
    parse_smbclient_ls,
    readable_shares,
    strip_smbclient_noise,
)

__all__ = [
    "PEEK_MAX_FILES",
    "SMB_SERVICE_NAMES",
    "SmbEntry",
    "SmbFinding",
    "SmbModule",
    "SmbStep",
    "anon_credential",
    "backslash_unc",
    "escaped_unc",
    "forward_unc",
    "is_share_peekable",
    "netexec_auth_ok",
    "parse_smb_tool",
    "parse_smbclient_ls",
    "peek_snippet",
    "readable_shares",
    "strip_smbclient_noise",
    "to_backslash_command",
    "to_escaped_command",
]


def is_share_peekable(entry: SmbEntry) -> bool:
    return _peek_is_peekable(entry.name, entry.is_dir, entry.size)


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


_UNC_IN_COMMAND = re.compile(r"//(?P<host>[^/\s]+)/(?P<share>\S*)")


def to_backslash_command(command: str) -> str:
    # //target/share -> \\target\share (Windows cmd form)
    return _UNC_IN_COMMAND.sub(lambda m: f"\\\\{m.group('host')}\\{m.group('share')}", command)


def to_escaped_command(command: str) -> str:
    # //target/share -> \\\\target\\share (bash-escaped form)
    return _UNC_IN_COMMAND.sub(
        lambda m: f"\\\\\\\\{m.group('host')}\\\\{m.group('share')}", command
    )


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
        # quote the UNC so a legal multi-word share name ("Team Share") stays one argv token
        unc = shlex.quote(f"//{host}/{share}")
        return [
            SmbStep(
                Command(
                    "smb",
                    f"smbclient {unc} {auth} -c 'ls'",
                    f"Root listing of share {share}.",
                    "< 30s",
                    f"smb/shares/{safe}-ls.txt",
                ),
            )
        ]

    def share_peek_step(self, target: Target, share: str, name: str, method: str) -> SmbStep:
        # stream a small, already-listed text file to stdout (§12: bounded triage read). smbclient
        # uses backslash paths inside a share; the status line it prints is stripped from the peek.
        host = target.ip
        auth = "-U 'guest%'" if method == "guest" else "-N"
        unc = shlex.quote(f"//{host}/{share}")
        inner = f'get "{name.replace("/", chr(92))}" -'
        digest = hashlib.sha1(f"{share}/{name}".encode(), usedforsecurity=False).hexdigest()[:8]
        slug = re.sub(r"[^A-Za-z0-9._-]", "-", f"{share}-{name}").strip("-")[:40] or "file"
        return SmbStep(
            Command(
                "smb",
                f"smbclient {unc} {auth} -c {shlex.quote(inner)}",
                f"Peek: preview the head of {share}/{name} (small text file).",
                "< 15s",
                f"smb/peek/{slug}-{digest}.txt",
            ),
        )

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
