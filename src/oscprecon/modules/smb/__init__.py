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
    dedup_share_findings,
    netexec_auth_ok,
    parse_smb_tool,
    parse_smbclient_ls,
    readable_shares,
    strip_smbclient_noise,
    writable_shares,
)
from oscprecon.recon_auth import ReconAuth

__all__ = [
    "PEEK_MAX_FILES",
    "SMB_SERVICE_NAMES",
    "SmbEntry",
    "SmbFinding",
    "SmbModule",
    "SmbStep",
    "anon_credential",
    "credentialed_credential",
    "backslash_unc",
    "escaped_unc",
    "forward_unc",
    "is_share_peekable",
    "netexec_auth_ok",
    "parse_smb_tool",
    "dedup_share_findings",
    "parse_smbclient_ls",
    "peek_snippet",
    "readable_shares",
    "strip_smbclient_noise",
    "writable_shares",
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


def credentialed_credential(target: Target, auth: ReconAuth) -> Credential:
    return Credential(
        username=auth.username,
        secret=auth.secret,
        secret_type=auth.secret_type,
        domain=auth.domain or target.hostname or "",
        source="smb-authenticated-enum",
        notes="SMB authenticated session succeeded",
    )


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
                "enum4linux",
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

    def credentialed_steps(self, target: Target, auth: ReconAuth) -> list[SmbStep]:
        # The same share/permission enumeration as null_session_steps/guest_steps, but as a
        # credential the operator already holds. Not a guess and not a tier change (§11 is about
        # GUESSING) — this is the authenticated enumeration you run the moment http/ftp/a share
        # hands you a password, and it returns far more than any anonymous pass.
        host = target.ip
        base = f"smb/{auth.output_slug}"
        return [
            SmbStep(
                Command(
                    "smb",
                    f"netexec smb {host} {auth.netexec_args()} --shares",
                    f"Shares + permissions as {auth.label}.",
                    "< 30s",
                    f"{base}/netexec-shares.txt",
                ),
                "netexec-shares",
            ),
            SmbStep(
                Command(
                    "smb",
                    f"smbclient -L //{host}/ {auth.smbclient_auth()}",
                    f"List shares as {auth.label}.",
                    "< 30s",
                    f"{base}/smbclient-L.txt",
                ),
                "smbclient-shares",
            ),
            SmbStep(
                Command(
                    "smb",
                    f"smbmap -H {host} {auth.smbmap_args()}",
                    "Share permissions with read/write flags per share.",
                    "< 1 min",
                    f"{base}/smbmap.txt",
                ),
                "smbmap",
            ),
        ]

    def followup_steps(self, target: Target, auth: ReconAuth) -> list[SmbStep]:
        host = target.ip
        nxc = auth.netexec_args()
        base = "smb" if auth.anonymous else f"smb/{auth.output_slug}"
        steps = [
            SmbStep(
                Command(
                    "smb",
                    f"netexec smb {host} {nxc} --users",
                    "Enumerate domain users.",
                    "< 30s",
                    f"{base}/users.txt",
                ),
                "netexec-users",
            ),
            SmbStep(
                Command(
                    "smb",
                    f"netexec smb {host} {nxc} --pass-pol",
                    "Password policy.",
                    "< 30s",
                    f"{base}/pass-pol.txt",
                ),
                "netexec-passpol",
            ),
            SmbStep(
                Command(
                    "smb",
                    f"netexec smb {host} {nxc} --rid-brute 10000",
                    "RID cycling (recon, not a credential brute).",
                    "1-5 min",
                    f"{base}/rid-brute.txt",
                ),
                "netexec-ridbrute",
            ),
            SmbStep(
                Command(
                    "smb",
                    f"rpcclient {auth.rpcclient_auth()} {host} -c 'enumdomusers'",
                    f"RPC user enumeration as {auth.label}.",
                    "< 30s",
                    f"{base}/rpcclient-enumdomusers.txt",
                ),
                "rpcclient-users",
            ),
        ]
        if auth.anonymous:
            return steps
        # a real credential unlocks enumeration an anonymous session never reaches
        return steps + [
            SmbStep(
                Command(
                    "smb",
                    f"netexec smb {host} {nxc} --groups",
                    "Domain groups (needs a credential).",
                    "< 30s",
                    f"{base}/groups.txt",
                ),
                "netexec-groups",
            ),
            SmbStep(
                Command(
                    "smb",
                    f"netexec smb {host} {nxc} --loggedon-users",
                    "Sessions currently logged on — who else to target.",
                    "< 30s",
                    f"{base}/loggedon-users.txt",
                ),
                "netexec-loggedon",
            ),
            SmbStep(
                Command(
                    "smb",
                    f"netexec smb {host} {nxc} --local-groups",
                    "Local groups — is this account a local admin anywhere?",
                    "< 30s",
                    f"{base}/local-groups.txt",
                ),
                "netexec-localgroups",
            ),
            SmbStep(
                Command(
                    "smb",
                    f"netexec smb {host} {nxc} --spider-plus",
                    "Spider every readable share's file index (metadata only, no download).",
                    "1-5 min",
                    f"{base}/spider-plus.txt",
                ),
                "netexec-spider",
            ),
        ]

    def share_steps(self, target: Target, share: str, auth: ReconAuth) -> list[SmbStep]:
        host = target.ip
        smb_auth = auth.smbclient_auth()
        safe = share.replace("$", "").replace("/", "-") or "share"
        # hash the raw name so 'C' and 'C$' (or 'Users'/'Users$') don't collide to the same
        # file and overwrite each other's listing.
        digest = hashlib.sha1(share.encode(), usedforsecurity=False).hexdigest()[:8]
        # quote the UNC so a legal multi-word share name ("Team Share") stays one argv token
        unc = shlex.quote(f"//{host}/{share}")
        # a credentialed walk of the same share must not overwrite the anonymous snapshot of it —
        # the two listings differ, and which one you are looking at has to be unambiguous.
        base = "smb/shares" if auth.anonymous else f"smb/{auth.output_slug}/shares"
        return [
            SmbStep(
                Command(
                    "smb",
                    f"smbclient {unc} {smb_auth} -c 'ls'",
                    f"Root listing of share {share}.",
                    "< 30s",
                    f"{base}/{safe}-{digest}-ls.txt",
                ),
            )
        ]

    def share_peek_step(self, target: Target, share: str, name: str, auth: ReconAuth) -> SmbStep:
        # stream a small, already-listed text file to stdout (§12: bounded triage read). smbclient
        # uses backslash paths inside a share; the status line it prints is stripped from the peek.
        host = target.ip
        smb_auth = auth.smbclient_auth()
        unc = shlex.quote(f"//{host}/{share}")
        # '/' is smbclient's in-share path separator (kept as '\'); escape an embedded double-quote
        # for smbclient's OWN parser (shlex.quote below only guards the shell) so a name like
        # a"b.txt can't terminate smbclient's quoted get argument and mis-target a different file.
        smb_path = name.replace("/", chr(92)).replace('"', '\\"')
        inner = f'get "{smb_path}" -'
        digest = hashlib.sha1(f"{share}/{name}".encode(), usedforsecurity=False).hexdigest()[:8]
        slug = re.sub(r"[^A-Za-z0-9._-]", "-", f"{share}-{name}").strip("-")[:40] or "file"
        base = "smb/peek" if auth.anonymous else f"smb/{auth.output_slug}/peek"
        return SmbStep(
            Command(
                "smb",
                f"smbclient {unc} {smb_auth} -c {shlex.quote(inner)}",
                f"Peek: preview the head of {share}/{name} (small text file).",
                "< 15s",
                f"{base}/{slug}-{digest}.txt",
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
