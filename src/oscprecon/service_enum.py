from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial

from oscprecon import findings, shell
from oscprecon.models import Credential, Finding, Target
from oscprecon.modules.dns import DnsFinding, DnsModule, parse_dns_tool
from oscprecon.modules.ftp import (
    FtpFinding,
    FtpModule,
    dedup_ftp_findings,
    is_peekable,
    nmap_anon_ok,
    parse_ftp_listing,
    parse_ftp_tool,
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
from oscprecon.modules.peek import PEEK_MAX_FILES, peek_snippet
from oscprecon.modules.smb import (
    SmbFinding,
    SmbModule,
    SmbStep,
    anon_credential,
    dedup_share_findings,
    is_share_peekable,
    netexec_auth_ok,
    parse_smb_tool,
    parse_smbclient_ls,
    readable_shares,
    strip_smbclient_noise,
    writable_shares,
)
from oscprecon.modules.ssh import SshFinding, SshModule, parse_ssh_tool
from oscprecon.parsing import run_parser
from oscprecon.profile import Profile

# The Tier-1 service enumeration ENGINE — Qt-free, so the GUI worker and `nabu-cli enum` run the
# SAME code. They used to be two implementations: the GUI drove the full conditional sequence
# (SMB null -> guest -> follow-ups -> share walk -> content peek; FTP's bounded BFS + peek) while
# the CLI ran only each module's first phase and stopped. Same command, two different depths of
# recon, and nothing said so.
#
# Each engine takes an `on_line` sink and an optional cancel Event; the Qt workers wrap these and
# forward to their signals. Nothing here imports PySide6 — `nabu-cli` must stay Qt-free.

_STEP_TIMEOUT_S = 300.0  # per-step watchdog: enum steps are quick, this only kills a tarpit [#24]

CANCELLED_NOTE = "⚠ recon cancelled — results are partial"


@dataclass
class EnumResult:
    """What a Tier-1 service enumeration produced: the operator-facing summary, plus any anonymous
    credential the run established (SMB null/guest, anonymous FTP, anonymous LDAP bind)."""

    summary: list[str]
    creds: list[Credential] = field(default_factory=list)


class _Engine:
    def __init__(
        self,
        profile: Profile,
        on_line: Callable[[str], None] | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        self._profile = profile
        self._on_line = on_line or (lambda _line: None)
        self._cancel = cancel

    def _emit(self, line: str) -> None:
        self._on_line(line)

    def _cancelled(self) -> bool:
        return self._cancel is not None and self._cancel.is_set()

    def _run_step(self, shell_line: str, output_rel: str) -> str:
        base = self._profile.directory
        out = base / output_rel
        shell.run(
            shell_line,
            out,
            cwd=base,
            cancel=self._cancel,
            on_line=self._emit,
            timeout=_STEP_TIMEOUT_S,
        )
        try:
            return out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def run(self) -> EnumResult:
        raise NotImplementedError


def _suggest_tips(module: object, collected: list[object], service: str) -> list[str]:
    # parity with the CLI enum + SimpleReconWorker: surface the module's suggest() decision-aids in
    # the GUI too (SMB-signing->relay, FTP-anon, SSH-password-auth, DNS-zone-transfer, LDAP-anon).
    # The bespoke findings carry kind/value/detail; wrap as generic Findings (what suggest reads).
    suggest = getattr(module, "suggest", None)
    if suggest is None:
        return []
    generic = [
        Finding(
            service=service,
            title="",
            detail=str(getattr(f, "detail", "")),
            fields={"kind": str(getattr(f, "kind", "")), "value": str(getattr(f, "value", ""))},
        )
        for f in collected
    ]
    return [f"→ {tip}" for tip in suggest(generic)]


@dataclass
class SmbReconResult(EnumResult):
    pass


class SmbEnum(_Engine):
    def __init__(
        self,
        profile: Profile,
        mode: str,
        on_line: Callable[[str], None] | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        super().__init__(profile, on_line, cancel)
        self._mode = mode
        self._module = SmbModule()

    def _run_phase(self, steps: list[SmbStep]) -> tuple[list[SmbFinding], bool]:
        # why: SMB Tier-1 is a conditional sequence, so auth must be detected between phases on
        # this thread — a single CommandWorker can't branch on a share listing's result.
        base = self._profile.directory
        found: list[SmbFinding] = []
        auth_ok = False
        for step in steps:
            if self._cancelled():
                break
            out = base / step.command.output_file
            shell.run(
                step.command.shell_line,
                out,
                cwd=base,
                cancel=self._cancel,
                on_line=self._emit,
                timeout=_STEP_TIMEOUT_S,  # bug #6: a hung enum4linux-ng/tarpit wedged this worker
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
                    on_line=self._emit,
                )
            )
            if step.tool == "netexec-shares" and netexec_auth_ok(text):
                auth_ok = True
        # enum4linux-ng's RPC null session counts too. netexec and enum4linux routinely disagree on
        # a Windows/Samba box — netexec gets STATUS_ACCESS_DENIED while enum4linux's RPC session
        # goes through — and gating only on netexec meant the follow-ups, the share walk and the
        # anonymous credential were all skipped while the findings pane showed a working null
        # session and a READ share. The summary then said "Anonymous access: none". [review]
        if not auth_ok and any(f.kind == "auth" and "session" in f.value for f in found):
            auth_ok = True
        return found, auth_ok

    def run(self) -> SmbReconResult:
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
            collected += self._walk_shares(target, method, readable_shares(collected))

        # collapse the same share seen by smbclient -L (name only) + netexec --shares (name + perms)
        # into one finding, unioning READ/WRITE — else it persists twice (blank + WRITE). [Abducted]
        collected = dedup_share_findings(collected)
        self._write_findings(collected)
        return SmbReconResult(self._summarize(collected, method), creds)

    def _run_smb_step(self, step: SmbStep) -> str:
        base = self._profile.directory
        out = base / step.command.output_file
        shell.run(
            step.command.shell_line,
            out,
            cwd=base,
            cancel=self._cancel,
            on_line=self._emit,
            timeout=_STEP_TIMEOUT_S,  # bug #6: match the watchdog the other service workers use
        )
        try:
            return out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _walk_shares(self, target: Target, method: str, shares: list[str]) -> list[SmbFinding]:
        # list each readable share's root, surface its files as findings, and peek small text ones —
        # a bounded content triage across all shares (§12), never bulk exfil.
        found: list[SmbFinding] = []
        budget = PEEK_MAX_FILES
        for share in dict.fromkeys(shares):
            if self._cancelled():
                break
            ls_step = self._module.share_steps(target, share, method)[0]
            for entry in parse_smbclient_ls(self._run_smb_step(ls_step)):
                path = f"{share}/{entry.name}"
                detail = "" if entry.is_dir else f"{entry.size} bytes"
                found.append(SmbFinding("dir" if entry.is_dir else "file", path, detail))
                if budget > 0 and is_share_peekable(entry):
                    step = self._module.share_peek_step(target, share, entry.name, method)
                    snippet = peek_snippet(strip_smbclient_noise(self._run_smb_step(step)))
                    found.append(SmbFinding("peek", path, snippet))
                    budget -= 1
        return found

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
            writable = set(writable_shares(collected))
            summary.append(f"Shares ({len(names)}):")
            for n in names:
                access = [a for a, s in (("READ", readable), ("WRITE", writable)) if n in s]
                summary.append(f"  {n}" + (f" [{','.join(access)}]" if access else ""))
        share_files = [f.value for f in collected if f.kind == "file"]
        if share_files:
            summary.append(f"Share files ({len(share_files)}):")
            summary.extend(f"  {f}" for f in sorted(set(share_files))[:20])
        peeks = [(f.value, f.detail) for f in collected if f.kind == "peek"]
        if peeks:
            summary.append(f"Peeked contents ({len(peeks)}):")
            summary.extend(f"  {path} → {snippet}" for path, snippet in peeks)
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
        summary.extend(_suggest_tips(self._module, list(collected), "smb"))
        return summary or ["No SMB findings."]


_FTP_MAX_DIRS = 25
_FTP_MAX_DEPTH = 3


@dataclass
class FtpReconResult(EnumResult):
    pass


class FtpEnum(_Engine):
    def __init__(
        self,
        profile: Profile,
        mode: str,
        port: int,
        on_line: Callable[[str], None] | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        super().__init__(profile, on_line, cancel)
        self._mode = mode
        self._port = port
        self._module = FtpModule()

    def _run_step(self, shell_line: str, output_rel: str) -> str:
        base = self._profile.directory
        out = base / output_rel
        # watchdog: a single enum step (banner/listing/peek) is quick — a slow-loris / tarpit target
        # that trickles bytes forever must not wedge the sole worker slot until the user cancels.
        shell.run(
            shell_line,
            out,
            cwd=base,
            timeout=_STEP_TIMEOUT_S,
            cancel=self._cancel,
            on_line=self._emit,
        )
        try:
            return out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def run(self) -> FtpReconResult:
        target = self._profile.target
        module = self._module
        collected: list[FtpFinding] = []

        nmap_text = ""
        for step in module.banner_steps(target, self._port):
            if self._cancelled():
                break
            nmap_text = self._run_step(step.command.shell_line, step.command.output_file)
            if step.tool:
                collected += run_parser(
                    partial(parse_ftp_tool, step.tool, nmap_text),
                    label=f"ftp {step.tool}",
                    on_line=self._emit,
                )
        anon = nmap_anon_ok(nmap_text)

        walk = self._walk(target, recurse=self._mode == "full")
        collected += walk
        if any(f.kind in ("file", "dir") for f in walk):
            anon = True  # a non-empty anonymous listing confirms anon even if nmap was inconclusive

        # nmap ftp-anon and the curl walk both list the root dir — collapse the overlap so a file
        # isn't reported (and persisted) twice; the walk's richer size+ext detail wins.
        collected = dedup_ftp_findings(collected)
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
            if self._cancelled():
                break
            path, depth = queue.pop(0)
            if path in seen:
                continue
            seen.add(path)
            step = module.list_step(target, path, self._port)
            text = self._run_step(step.command.shell_line, step.command.output_file)
            listed += 1
            for entry in run_parser(
                partial(parse_ftp_listing, text), label="ftp listing", on_line=self._emit
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
            self._emit(f"[ftp] walk bounded at {_FTP_MAX_DIRS} dirs — list deeper paths via Tier-2")
        return findings

    def _peek_files(self, target: Target, paths: list[str]) -> list[FtpFinding]:
        # bounded content triage: fetch the head of up to PEEK_MAX_FILES small text files so you
        # can eyeball what's inside without an explicit download of each.
        out: list[FtpFinding] = []
        for path in paths[:PEEK_MAX_FILES]:
            if self._cancelled():
                break
            step = self._module.peek_step(target, path, self._port)
            text = self._run_step(step.command.shell_line, step.command.output_file)
            out.append(FtpFinding("peek", path, peek_snippet(text)))
        if len(paths) > PEEK_MAX_FILES:
            self._emit(f"[ftp] peeked {PEEK_MAX_FILES}/{len(paths)} small files — rest via Tier-2")
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
        summary.extend(_suggest_tips(self._module, list(collected), "ftp"))
        return summary


@dataclass
class SshReconResult(EnumResult):
    pass


class SshEnum(_Engine):
    def __init__(
        self,
        profile: Profile,
        port: int,
        on_line: Callable[[str], None] | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        super().__init__(profile, on_line, cancel)
        self._port = port
        self._module = SshModule()

    def _run_step(self, shell_line: str, output_rel: str) -> str:
        base = self._profile.directory
        out = base / output_rel
        # watchdog: a single enum step (banner/listing/peek) is quick — a slow-loris / tarpit target
        # that trickles bytes forever must not wedge the sole worker slot until the user cancels.
        shell.run(
            shell_line,
            out,
            cwd=base,
            timeout=_STEP_TIMEOUT_S,
            cancel=self._cancel,
            on_line=self._emit,
        )
        try:
            return out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def run(self) -> SshReconResult:
        target = self._profile.target
        collected: list[SshFinding] = []
        for step in self._module.recon_steps(target, self._port):
            if self._cancelled():
                break
            text = self._run_step(step.command.shell_line, step.command.output_file)
            if step.tool:
                collected += run_parser(
                    partial(parse_ssh_tool, step.tool, text),
                    label=f"ssh {step.tool}",
                    on_line=self._emit,
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
        summary.extend(_suggest_tips(self._module, list(collected), "ssh"))
        return summary or ["No SSH findings."]


@dataclass
class DnsReconResult(EnumResult):
    pass


class DnsEnum(_Engine):
    def __init__(
        self,
        profile: Profile,
        domain: str,
        port: int,
        on_line: Callable[[str], None] | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        super().__init__(profile, on_line, cancel)
        self._domain = domain
        self._port = port
        self._module = DnsModule()

    def _run_step(self, shell_line: str, output_rel: str) -> str:
        base = self._profile.directory
        out = base / output_rel
        # watchdog: a single enum step (banner/listing/peek) is quick — a slow-loris / tarpit target
        # that trickles bytes forever must not wedge the sole worker slot until the user cancels.
        shell.run(
            shell_line,
            out,
            cwd=base,
            timeout=_STEP_TIMEOUT_S,
            cancel=self._cancel,
            on_line=self._emit,
        )
        try:
            return out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def run(self) -> DnsReconResult:
        target = self._profile.target
        collected: list[DnsFinding] = []
        for step in self._module.recon_steps(target, self._domain or None, self._port):
            if self._cancelled():
                break
            text = self._run_step(step.command.shell_line, step.command.output_file)
            if step.tool:
                collected += run_parser(
                    partial(parse_dns_tool, step.tool, text),
                    label=f"dns {step.tool}",
                    on_line=self._emit,
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
        summary.extend(_suggest_tips(self._module, list(collected), "dns"))
        return summary or ["No DNS findings."]


@dataclass
class LdapReconResult(EnumResult):
    pass


class LdapEnum(_Engine):
    def __init__(
        self,
        profile: Profile,
        basedn: str,
        port: int,
        on_line: Callable[[str], None] | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        super().__init__(profile, on_line, cancel)
        self._basedn = basedn
        self._port = port
        self._module = LdapModule()

    def _run_step(self, shell_line: str, output_rel: str) -> str:
        base = self._profile.directory
        out = base / output_rel
        # watchdog: a single enum step (banner/listing/peek) is quick — a slow-loris / tarpit target
        # that trickles bytes forever must not wedge the sole worker slot until the user cancels.
        shell.run(
            shell_line,
            out,
            cwd=base,
            timeout=_STEP_TIMEOUT_S,
            cancel=self._cancel,
            on_line=self._emit,
        )
        try:
            return out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def run(self) -> LdapReconResult:
        target = self._profile.target
        module = self._module
        collected: list[LdapFinding] = []

        for step in module.rootdse_steps(target, self._port):
            if self._cancelled():
                break
            text = self._run_step(step.command.shell_line, step.command.output_file)
            if step.tool:
                collected += run_parser(
                    partial(parse_ldap_tool, step.tool, text),
                    label=f"ldap {step.tool}",
                    on_line=self._emit,
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
                    on_line=self._emit,
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
        summary.extend(_suggest_tips(self._module, list(collected), "ldap"))
        return summary


# public alias: what the GUI worker and the CLI both hold — an engine you call run() on.
EnumEngine = _Engine
