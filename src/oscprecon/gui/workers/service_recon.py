from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial

from PySide6.QtCore import Signal

from oscprecon import findings, shell
from oscprecon.gui.workers.base import CancellableThread
from oscprecon.models import Credential, Target
from oscprecon.modules.dns import DnsFinding, DnsModule, parse_dns_tool
from oscprecon.modules.ftp import (
    PEEK_MAX_FILES,
    FtpFinding,
    FtpModule,
    is_peekable,
    nmap_anon_ok,
    parse_ftp_listing,
    parse_ftp_tool,
    peek_snippet,
)
from oscprecon.modules.ftp import (
    anon_credential as ftp_anon_credential,
)
from oscprecon.modules.ldap import (
    LdapFinding,
    LdapModule,
    parse_ldap_tool,
    sanitize_basedn,
)
from oscprecon.modules.ldap import (
    anon_credential as ldap_anon_credential,
)
from oscprecon.modules.smb import (
    SmbFinding,
    SmbModule,
    SmbStep,
    anon_credential,
    netexec_auth_ok,
    parse_smb_tool,
    readable_shares,
)
from oscprecon.modules.ssh import SshFinding, SshModule, parse_ssh_tool
from oscprecon.parsing import run_parser
from oscprecon.profile import Profile


@dataclass
class SmbReconResult:
    summary: list[str]
    creds: list[Credential]


class SmbReconWorker(CancellableThread):
    line = Signal(str)
    done = Signal(object)  # SmbReconResult
    failed = Signal(str)

    def __init__(self, profile: Profile, mode: str) -> None:
        super().__init__()
        self._profile = profile
        self._mode = mode
        self._module = SmbModule()

    def run(self) -> None:
        try:
            result = self._drive()
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        self.done.emit(result)

    def _run_phase(self, steps: list[SmbStep]) -> tuple[list[SmbFinding], bool]:
        # why: SMB Tier-1 is a conditional sequence, so auth must be detected between phases on
        # this thread — a single CommandWorker can't branch on a share listing's result.
        base = self._profile.directory
        found: list[SmbFinding] = []
        auth_ok = False
        for step in steps:
            if self._cancel.is_set():
                break
            out = base / step.command.output_file
            shell.run(
                step.command.shell_line, out, cwd=base, cancel=self._cancel, on_line=self.line.emit
            )
            if not step.tool:
                continue
            try:
                text = out.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            found.extend(
                run_parser(
                    partial(parse_smb_tool, step.tool, text),
                    label=f"smb {step.tool}",
                    on_line=self.line.emit,
                )
            )
            if step.tool == "netexec-shares" and netexec_auth_ok(text):
                auth_ok = True
        return found, auth_ok

    def _drive(self) -> SmbReconResult:
        target = self._profile.target
        module = self._module
        collected: list[SmbFinding] = []

        banner, _ = self._run_phase(module.banner_steps(target))
        collected += banner

        method: str | None = None
        if self._mode in ("full", "null", "shares"):
            null_found, null_ok = self._run_phase(module.null_session_steps(target))
            collected += null_found
            if null_ok:
                method = "null"
        if self._mode in ("full", "guest", "shares"):
            guest_found, guest_ok = self._run_phase(module.guest_steps(target))
            collected += guest_found
            if guest_ok and method is None:
                method = "guest"

        creds: list[Credential] = []
        if method is not None:
            creds.append(anon_credential(target, method))
            if self._mode in ("full", "null", "guest"):
                followup, _ = self._run_phase(module.followup_steps(target, method))
                collected += followup
            # dedup: full/shares modes enumerate shares via both null and guest, so the same
            # readable share can appear twice — list each once (dict.fromkeys preserves order).
            for share in dict.fromkeys(readable_shares(collected)):
                self._run_phase(module.share_steps(target, share, method))

        self._write_findings(collected)
        return SmbReconResult(self._summarize(collected, method), creds)

    def _write_findings(self, collected: list[SmbFinding]) -> None:
        if not collected:
            return
        now = datetime.now(UTC).isoformat()
        findings.add_findings(self._profile.directory, [f.to_dict(now) for f in collected])

    def _summarize(self, collected: list[SmbFinding], method: str | None) -> list[str]:
        summary: list[str] = []
        signing = [f.value for f in collected if f.kind == "signing"]
        if signing:
            summary.append(f"SMB signing: {signing[-1]}")
        share_findings = [f for f in collected if f.kind == "share"]
        if share_findings:
            names = sorted({f.value for f in share_findings})
            readable = set(readable_shares(collected))
            summary.append(f"Shares ({len(names)}):")
            summary.extend(f"  {n}{' [READ]' if n in readable else ''}" for n in names)
        users = sorted({f.value for f in collected if f.kind == "user"})
        if users:
            shown = ", ".join(users[:10])
            more = "…" if len(users) > 10 else ""
            summary.append(f"Users ({len(users)}): {shown}{more}")
        for policy in (f for f in collected if f.kind == "policy"):
            summary.append(f"Policy — {policy.value}: {policy.detail}")
        if method is not None:
            summary.append(f"Anonymous access: {method} session OK")
        else:
            summary.append("Anonymous access: none (null/guest denied)")
        return summary or ["No SMB findings."]


_FTP_MAX_DIRS = 25
_FTP_MAX_DEPTH = 3


@dataclass
class FtpReconResult:
    summary: list[str]
    creds: list[Credential]


class FtpReconWorker(CancellableThread):
    line = Signal(str)
    done = Signal(object)  # FtpReconResult
    failed = Signal(str)

    def __init__(self, profile: Profile, mode: str, port: int) -> None:
        super().__init__()
        self._profile = profile
        self._mode = mode
        self._port = port
        self._module = FtpModule()

    def run(self) -> None:
        try:
            result = self._drive()
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        self.done.emit(result)

    def _run_step(self, shell_line: str, output_rel: str) -> str:
        base = self._profile.directory
        out = base / output_rel
        shell.run(shell_line, out, cwd=base, cancel=self._cancel, on_line=self.line.emit)
        try:
            return out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _drive(self) -> FtpReconResult:
        target = self._profile.target
        module = self._module
        collected: list[FtpFinding] = []

        nmap_text = ""
        for step in module.banner_steps(target, self._port):
            if self._cancel.is_set():
                break
            nmap_text = self._run_step(step.command.shell_line, step.command.output_file)
            if step.tool:
                collected += run_parser(
                    partial(parse_ftp_tool, step.tool, nmap_text),
                    label=f"ftp {step.tool}",
                    on_line=self.line.emit,
                )
        anon = nmap_anon_ok(nmap_text)

        walk = self._walk(target, recurse=self._mode == "full")
        collected += walk
        if any(f.kind in ("file", "dir") for f in walk):
            anon = True  # a non-empty anonymous listing confirms anon even if nmap was inconclusive

        creds = [ftp_anon_credential(target)] if anon else []
        self._write_findings(collected)
        return FtpReconResult(self._summarize(collected, anon), creds)

    def _walk(self, target: Target, recurse: bool) -> list[FtpFinding]:
        # bounded BFS: curl LISTs each directory (never downloads); depth + total-dir capped so the
        # snapshot is finite (§12). `seen` prevents symlink/loop re-listing.
        module = self._module
        findings: list[FtpFinding] = []
        seen: set[str] = set()
        queue: list[tuple[str, int]] = [("/", 0)]
        peekable: list[str] = []
        listed = 0
        while queue and listed < _FTP_MAX_DIRS:
            if self._cancel.is_set():
                break
            path, depth = queue.pop(0)
            if path in seen:
                continue
            seen.add(path)
            step = module.list_step(target, path, self._port)
            text = self._run_step(step.command.shell_line, step.command.output_file)
            listed += 1
            for entry in run_parser(
                partial(parse_ftp_listing, text), label="ftp listing", on_line=self.line.emit
            ):
                child = path.rstrip("/") + "/" + entry.name
                kind = "dir" if entry.is_dir else "file"
                ext = entry.extension or "no ext"
                detail = "" if entry.is_dir else f"{entry.size} bytes ({ext})"
                findings.append(FtpFinding(kind, child, detail))
                if is_peekable(entry):
                    peekable.append(child)
                if recurse and entry.is_dir and depth + 1 < _FTP_MAX_DEPTH:
                    queue.append((child + "/", depth + 1))
        findings.extend(self._peek_files(target, peekable))
        if queue:  # exited on the dir cap — say so, don't pretend the walk was exhaustive
            self.line.emit(
                f"[ftp] walk bounded at {_FTP_MAX_DIRS} dirs — list deeper paths via Tier-2"
            )
        return findings

    def _peek_files(self, target: Target, paths: list[str]) -> list[FtpFinding]:
        # bounded content triage: fetch the head of up to PEEK_MAX_FILES small text files so you
        # can eyeball what's inside without an explicit download of each.
        out: list[FtpFinding] = []
        for path in paths[:PEEK_MAX_FILES]:
            if self._cancel.is_set():
                break
            step = self._module.peek_step(target, path, self._port)
            text = self._run_step(step.command.shell_line, step.command.output_file)
            out.append(FtpFinding("peek", path, peek_snippet(text)))
        if len(paths) > PEEK_MAX_FILES:
            self.line.emit(
                f"[ftp] peeked {PEEK_MAX_FILES}/{len(paths)} small files — rest via Tier-2"
            )
        return out

    def _write_findings(self, collected: list[FtpFinding]) -> None:
        if not collected:
            return
        now = datetime.now(UTC).isoformat()
        findings.add_findings(self._profile.directory, [f.to_dict(now) for f in collected])

    def _summarize(self, collected: list[FtpFinding], anon: bool) -> list[str]:
        summary: list[str] = []
        banners = [f.value for f in collected if f.kind == "banner"]
        if banners:
            summary.append(f"Banner: {banners[0]}")
        dirs = sorted({f.value for f in collected if f.kind == "dir"})
        files = sorted({f.value for f in collected if f.kind == "file"})
        if dirs:
            summary.append(f"Directories ({len(dirs)}):")
            summary.extend(f"  {d}/" for d in dirs)
        if files:
            summary.append(f"Files ({len(files)}):")
            summary.extend(f"  {f}" for f in files)
        peeks = [(f.value, f.detail) for f in collected if f.kind == "peek"]
        if peeks:
            summary.append(f"Peeked contents ({len(peeks)}):")
            summary.extend(f"  {path} → {snippet}" for path, snippet in peeks)
        if any(f.kind == "note" and "bounce" in f.value for f in collected):
            summary.append("Note: FTP bounce accepted (recon)")
        summary.append("Anonymous access: allowed" if anon else "Anonymous access: denied")
        return summary


@dataclass
class SshReconResult:
    summary: list[str]


class SshReconWorker(CancellableThread):
    line = Signal(str)
    done = Signal(object)  # SshReconResult
    failed = Signal(str)

    def __init__(self, profile: Profile, port: int) -> None:
        super().__init__()
        self._profile = profile
        self._port = port
        self._module = SshModule()

    def run(self) -> None:
        try:
            result = self._drive()
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        self.done.emit(result)

    def _run_step(self, shell_line: str, output_rel: str) -> str:
        base = self._profile.directory
        out = base / output_rel
        shell.run(shell_line, out, cwd=base, cancel=self._cancel, on_line=self.line.emit)
        try:
            return out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _drive(self) -> SshReconResult:
        target = self._profile.target
        collected: list[SshFinding] = []
        for step in self._module.recon_steps(target, self._port):
            if self._cancel.is_set():
                break
            text = self._run_step(step.command.shell_line, step.command.output_file)
            if step.tool:
                collected += run_parser(
                    partial(parse_ssh_tool, step.tool, text),
                    label=f"ssh {step.tool}",
                    on_line=self.line.emit,
                )
        self._write_findings(collected)
        return SshReconResult(self._summarize(collected))

    def _write_findings(self, collected: list[SshFinding]) -> None:
        if not collected:
            return
        now = datetime.now(UTC).isoformat()
        findings.add_findings(self._profile.directory, [f.to_dict(now) for f in collected])

    def _summarize(self, collected: list[SshFinding]) -> list[str]:
        summary: list[str] = []
        banners = [f.value for f in collected if f.kind == "banner"]
        if banners:
            summary.append(f"Banner: {banners[0]}")
        hostkeys = [f.value for f in collected if f.kind == "hostkey"]
        if hostkeys:
            summary.append(f"Host keys ({len(hostkeys)}): {', '.join(hostkeys)}")
        weak = sorted({f.value for f in collected if f.kind == "algo-weak"})
        if weak:
            summary.append(f"Weak algorithms ({len(weak)}): {', '.join(weak)}")
        methods = [f.value for f in collected if f.kind == "auth"]
        if methods:
            summary.append(f"Auth methods: {', '.join(methods)}")
            if "password" in methods:
                summary.append("Password auth enabled — single default-cred checks are Tier-2")
        return summary or ["No SSH findings."]


@dataclass
class DnsReconResult:
    summary: list[str]


class DnsReconWorker(CancellableThread):
    line = Signal(str)
    done = Signal(object)  # DnsReconResult
    failed = Signal(str)

    def __init__(self, profile: Profile, domain: str, port: int) -> None:
        super().__init__()
        self._profile = profile
        self._domain = domain
        self._port = port
        self._module = DnsModule()

    def run(self) -> None:
        try:
            result = self._drive()
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        self.done.emit(result)

    def _run_step(self, shell_line: str, output_rel: str) -> str:
        base = self._profile.directory
        out = base / output_rel
        shell.run(shell_line, out, cwd=base, cancel=self._cancel, on_line=self.line.emit)
        try:
            return out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _drive(self) -> DnsReconResult:
        target = self._profile.target
        collected: list[DnsFinding] = []
        for step in self._module.recon_steps(target, self._domain or None, self._port):
            if self._cancel.is_set():
                break
            text = self._run_step(step.command.shell_line, step.command.output_file)
            if step.tool:
                collected += run_parser(
                    partial(parse_dns_tool, step.tool, text),
                    label=f"dns {step.tool}",
                    on_line=self.line.emit,
                )
        self._write_findings(collected)
        return DnsReconResult(self._summarize(collected))

    def _write_findings(self, collected: list[DnsFinding]) -> None:
        if not collected:
            return
        now = datetime.now(UTC).isoformat()
        findings.add_findings(self._profile.directory, [f.to_dict(now) for f in collected])

    def _summarize(self, collected: list[DnsFinding]) -> list[str]:
        summary: list[str] = []
        versions = [f.value for f in collected if f.kind == "version"]
        if versions:
            summary.append(f"Version: {versions[0]}")
        transfer = [f for f in collected if f.kind == "zone-transfer"]
        if transfer:
            latest = transfer[-1]
            summary.append(f"Zone transfer: {latest.value} ({latest.detail})")
        recursion = [f.value for f in collected if f.kind == "recursion"]
        if recursion:
            summary.append(f"Recursion: {recursion[-1]}")
        records = sorted({f.value for f in collected if f.kind == "record"})
        if records:
            summary.append(f"Records ({len(records)}):")
            summary.extend(f"  {r}" for r in records)
        return summary or ["No DNS findings."]


@dataclass
class LdapReconResult:
    summary: list[str]
    creds: list[Credential]


class LdapReconWorker(CancellableThread):
    line = Signal(str)
    done = Signal(object)  # LdapReconResult
    failed = Signal(str)

    def __init__(self, profile: Profile, basedn: str, port: int) -> None:
        super().__init__()
        self._profile = profile
        self._basedn = basedn
        self._port = port
        self._module = LdapModule()

    def run(self) -> None:
        try:
            result = self._drive()
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        self.done.emit(result)

    def _run_step(self, shell_line: str, output_rel: str) -> str:
        base = self._profile.directory
        out = base / output_rel
        shell.run(shell_line, out, cwd=base, cancel=self._cancel, on_line=self.line.emit)
        try:
            return out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _drive(self) -> LdapReconResult:
        target = self._profile.target
        module = self._module
        collected: list[LdapFinding] = []

        for step in module.rootdse_steps(target, self._port):
            if self._cancel.is_set():
                break
            text = self._run_step(step.command.shell_line, step.command.output_file)
            if step.tool:
                collected += run_parser(
                    partial(parse_ldap_tool, step.tool, text),
                    label=f"ldap {step.tool}",
                    on_line=self.line.emit,
                )

        # base DN for the user search: prefer a discovered naming context, else the entered value.
        # sanitize_basedn drops anything not DN-syntax (a hostile server-returned context too).
        discovered = [f.value for f in collected if f.kind == "naming-context"]
        basedn: str | None = None
        for candidate in [*discovered, self._basedn]:
            basedn = sanitize_basedn(candidate)
            if basedn is not None:
                break

        if basedn is not None:
            user_step = module.user_search_step(target, basedn, self._port)
            if user_step is not None:
                text = self._run_step(user_step.command.shell_line, user_step.command.output_file)
                collected += run_parser(
                    partial(parse_ldap_tool, user_step.tool, text),
                    label=f"ldap {user_step.tool}",
                    on_line=self.line.emit,
                )

        anon = any(f.kind == "bind" for f in collected)
        creds = [ldap_anon_credential(target)] if anon else []
        self._write_findings(collected)
        return LdapReconResult(self._summarize(collected, basedn, anon), creds)

    def _write_findings(self, collected: list[LdapFinding]) -> None:
        if not collected:
            return
        now = datetime.now(UTC).isoformat()
        findings.add_findings(self._profile.directory, [f.to_dict(now) for f in collected])

    def _summarize(self, collected: list[LdapFinding], basedn: str | None, anon: bool) -> list[str]:
        summary: list[str] = []
        contexts = sorted({f.value for f in collected if f.kind == "naming-context"})
        if contexts:
            summary.append(f"Naming contexts ({len(contexts)}):")
            summary.extend(f"  {c}" for c in contexts)
        for info in (f for f in collected if f.kind == "info"):
            summary.append(f"Info: {info.value}")
        users = sorted({f.value for f in collected if f.kind == "user"})
        if users:
            shown = ", ".join(users[:15])
            more = "…" if len(users) > 15 else ""
            summary.append(f"Users ({len(users)}): {shown}{more}")
        if basedn is not None:
            summary.append(f"Base DN used: {basedn}")
        summary.append("Anonymous bind: allowed" if anon else "Anonymous bind: denied")
        return summary
