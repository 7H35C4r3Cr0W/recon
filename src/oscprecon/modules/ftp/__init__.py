from __future__ import annotations

import hashlib
import re
import shlex
from dataclasses import dataclass
from urllib.parse import quote

from oscprecon.models import Command, Credential, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.ftp.parsers import (
    FtpEntry,
    FtpFinding,
    dedup_ftp_findings,
    nmap_anon_ok,
    parse_ftp_listing,
    parse_ftp_tool,
    peek_snippet,
    subdirs,
)
from oscprecon.modules.peek import PEEK_MAX_BYTES, PEEK_MAX_FILES
from oscprecon.modules.peek import is_peekable as _peek_is_peekable
from oscprecon.recon_auth import ReconAuth

__all__ = [
    "FTP_SERVICE_NAMES",
    "PEEK_MAX_BYTES",
    "PEEK_MAX_FILES",
    "FtpEntry",
    "FtpFinding",
    "FtpModule",
    "FtpStep",
    "anon_credential",
    "dedup_ftp_findings",
    "ftp_base_url",
    "ftp_dir_url",
    "ftp_file_url",
    "is_peekable",
    "nmap_anon_ok",
    "parse_ftp_listing",
    "parse_ftp_tool",
    "peek_snippet",
    "subdirs",
]

FTP_SERVICE_NAMES = frozenset({"ftp", "ftp-data", "ftps", "ftps-data"})
_FTP_PORTS = frozenset({21})


def is_peekable(entry: FtpEntry) -> bool:
    return _peek_is_peekable(entry.name, entry.is_dir, entry.size)  # shared triage gate (§12)


def ftp_file_url(target: str, port: int, path: str) -> str:
    # a FILE url (no trailing '/') so curl DOWNLOADS it; the small file is fetched whole to preview
    raw = path if path.startswith("/") else "/" + path
    return ftp_base_url(target, port) + quote(raw, safe="/")


@dataclass
class FtpStep:
    command: Command
    tool: str = ""  # parser key for the output, or "" when the output is not parsed


def ftp_base_url(target: str, port: int = 21) -> str:
    return f"ftp://{target}" if port == 21 else f"ftp://{target}:{port}"


def ftp_dir_url(target: str, port: int, path: str) -> str:
    # why: the path segments come from a target-controlled listing, so URL-encode them (keeping '/')
    # and always end in '/' — curl LISTs a directory URL but DOWNLOADS a file URL, and we only ever
    # want a listing during the auto-walk (§12: download is an explicit Tier-2 click).
    raw = path if path.startswith("/") else "/" + path
    encoded = quote(raw, safe="/")
    if not encoded.endswith("/"):
        encoded += "/"
    return ftp_base_url(target, port) + encoded


def _curl_login(auth: ReconAuth) -> str:
    # a trailing space only when there IS a credential, so anonymous commands stay byte-identical
    flag = auth.curl_userpass()
    return f"{flag} " if flag else ""


def _dir_slug(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "-", path.strip("/")) or "root"


def anon_credential(target: Target) -> Credential:
    return Credential(
        username="anonymous",
        secret="",
        secret_type="password",
        domain=target.hostname or "",
        source="ftp-anon-enum",
        notes="Anonymous FTP login succeeded",
    )


class FtpModule(Module):
    name = "ftp"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in FTP_SERVICE_NAMES or s.port in _FTP_PORTS
            for s in scan_results.services
        )

    def banner_steps(self, target: Target, port: int = 21) -> list[FtpStep]:
        host = target.ip
        return [
            FtpStep(
                Command(
                    "ftp",
                    f"nmap -sV --script ftp-anon,ftp-syst,ftp-bounce -p {port} {host}",
                    "Banner, anonymous-login check, system type, and bounce check (all recon).",
                    "< 1 min",
                    "ftp/nmap-ftp.txt",
                ),
                "nmap-ftp",
            )
        ]

    def anon_steps(
        self, target: Target, port: int = 21, auth: ReconAuth | None = None
    ) -> list[FtpStep]:
        url = ftp_dir_url(target.ip, port, "/")
        who = auth or ReconAuth.null()
        base = "ftp" if who.anonymous else f"ftp/{who.output_slug}"
        login = _curl_login(who)
        return [
            FtpStep(
                Command(
                    "ftp",
                    f"curl -s --connect-timeout 10 --max-time 60 {login}{shlex.quote(url)}",
                    f"Root directory listing as {who.label if not who.anonymous else 'anonymous'}.",
                    "< 30s",
                    f"{base}/curl-root.txt",
                ),
                "curl-list",
            )
        ]

    def list_step(
        self, target: Target, path: str, port: int = 21, auth: ReconAuth | None = None
    ) -> FtpStep:
        url = ftp_dir_url(target.ip, port, path)
        who = auth or ReconAuth.null()
        base = "ftp" if who.anonymous else f"ftp/{who.output_slug}"
        # why: the slug is lossy (many paths collapse to one), so append a hash of the full path —
        # otherwise two distinct dirs (e.g. '/' and '/root', '/a/b' and '/a-b') clobber each other's
        # on-disk listing snapshot.
        digest = hashlib.sha1(path.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]
        return FtpStep(
            Command(
                "ftp",
                f"curl -s --connect-timeout 10 --max-time 60 {_curl_login(who)}{shlex.quote(url)}",
                f"Listing of {path}.",
                "< 30s",
                f"{base}/dirs/{_dir_slug(path)}-{digest}.txt",
            ),
            "curl-list",
        )

    def peek_step(
        self, target: Target, path: str, port: int = 21, auth: ReconAuth | None = None
    ) -> FtpStep:
        # fetch the HEAD of a small, already-listed text file (§12: bounded read). `-r 0-N` caps the
        # transfer by BYTES, not just --max-time (which bounds time only): a target under-reporting
        # a file's size in its listing can't force a multi-GB download / OOM on a fast link. [#23]
        url = ftp_file_url(target.ip, port, path)
        digest = hashlib.sha1(path.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]
        who = auth or ReconAuth.null()
        base = "ftp" if who.anonymous else f"ftp/{who.output_slug}"
        return FtpStep(
            Command(
                "ftp",
                f"curl -s --connect-timeout 10 --max-time 15 -r 0-{PEEK_MAX_BYTES - 1} "
                f"{_curl_login(who)}{shlex.quote(url)}",
                f"Peek: preview the head of {path} (small text file).",
                "< 15s",
                f"{base}/peek/{_dir_slug(path)}-{digest}.txt",
            ),
            "peek",
        )

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        steps = self.banner_steps(target) + self.anon_steps(target)
        return [step.command for step in steps]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        raw: list[FtpFinding] = []
        for tool, text in raw_outputs.items():
            raw += parse_ftp_tool(tool, text)
        return [
            Finding(
                service="ftp",
                title=f"{ff.kind}: {ff.value}",
                detail=ff.detail,
                fields={"kind": ff.kind, "value": ff.value, "detail": ff.detail},
            )
            for ff in dedup_ftp_findings(raw)  # nmap + curl both list root — collapse the overlap
        ]

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        if any(
            f.fields.get("kind") == "auth" and f.fields.get("value") == "anonymous"
            for f in findings
        ):
            out.append(
                "Anonymous FTP allowed — read-only snapshot taken; "
                "download specific files via Tier-2 (never bulk auto)."
            )
        if any(
            f.fields.get("kind") == "note" and "bounce" in f.fields.get("value", "")
            for f in findings
        ):
            out.append(
                "FTP bounce accepted — can proxy port scans; note for pivoting (recon only)."
            )
        if any(
            f.fields.get("kind") == "note" and f.fields.get("value") == "pasv-private-ip"
            for f in findings
        ):
            out.append(
                "PASV returned an unreachable IP — the passive listing will hang/fail. Retry in "
                "ACTIVE mode: wget -m --no-passive-ftp 'ftp://anonymous:anonymous@{target}/' "
                "(or curl --ftp-port - 'ftp://{target}/')."
            )
        return out
