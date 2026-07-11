from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDockWidget,
    QFileDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from oscprecon import config, findings, references, shell
from oscprecon.gui.simple_recon import SIMPLE_SPECS
from oscprecon.gui.widgets.notes_pane import NotesPane
from oscprecon.gui.widgets.reference_pane import ReferencePane
from oscprecon.gui.widgets.service_tree import ServiceTree
from oscprecon.gui.widgets.tool_panel import ToolPanel
from oscprecon.gui.widgets.wordlist_picker import WordlistPicker
from oscprecon.models import Credential, DiscoveredService, Finding, Target
from oscprecon.modules.base import Module
from oscprecon.modules.dns import DnsFinding, DnsModule, parse_dns_tool
from oscprecon.modules.ftp import (
    FtpFinding,
    FtpModule,
    nmap_anon_ok,
    parse_ftp_listing,
    parse_ftp_tool,
)
from oscprecon.modules.ftp import (
    anon_credential as ftp_anon_credential,
)
from oscprecon.modules.http import default_url, detect_wordpress, parse_tool
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
from oscprecon.modules.vhost import parse_vhost_tool
from oscprecon.orchestrator import Orchestrator
from oscprecon.profile import Profile


class NewProfileDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("New Scan Profile")
        self._name = QLineEdit()
        self._ip = QLineEdit()
        self._box = QComboBox()
        self._box.addItem("(none)")

        form = QFormLayout()
        form.addRow("Profile name:", self._name)
        form.addRow("Target IP / host:", self._ip)
        form.addRow("Box (optional):", self._box)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def values(self) -> tuple[str, str]:
        return self._name.text().strip(), self._ip.text().strip()


class AddCredentialDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add Credential")
        self._username = QLineEdit()
        self._secret = QLineEdit()
        self._secret.setEchoMode(QLineEdit.EchoMode.Password)
        self._secret_type = QComboBox()
        self._secret_type.addItems(["password", "hash", "key"])
        self._domain = QLineEdit()
        self._source = QLineEdit()
        self._notes = QLineEdit()

        form = QFormLayout()
        form.addRow("Username:", self._username)
        form.addRow("Secret:", self._secret)
        form.addRow("Type:", self._secret_type)
        form.addRow("Domain:", self._domain)
        form.addRow("Source:", self._source)
        form.addRow("Notes:", self._notes)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def credential(self) -> Credential | None:
        username = self._username.text().strip()
        secret = self._secret.text()
        if not username or not secret:
            return None
        return Credential(
            username=username,
            secret=secret,
            secret_type=self._secret_type.currentText(),
            domain=self._domain.text().strip(),
            source=self._source.text().strip() or "manual",
            notes=self._notes.text().strip(),
        )


class NmapWorker(QThread):
    line = Signal(str)
    done = Signal(int)
    failed = Signal(str)

    def __init__(self, profile: Profile, udp_full: bool = False) -> None:
        super().__init__()
        self._profile = profile
        self._udp_full = udp_full

    def run(self) -> None:
        try:
            orch = Orchestrator(self._profile, on_line=self.line.emit, udp_full=self._udp_full)
            orch.run_nmap()
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        self.done.emit(len(self._profile.discovered_services))


class CommandWorker(QThread):
    line = Signal(str)
    done = Signal(int)
    failed = Signal(str)

    def __init__(self, shell_line: str, output_file: Path, cwd: Path | None = None) -> None:
        super().__init__()
        self._shell_line = shell_line
        self._output_file = output_file
        self._cwd = cwd

    def run(self) -> None:
        try:
            result = shell.run(
                self._shell_line, self._output_file, cwd=self._cwd, on_line=self.line.emit
            )
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        self.done.emit(result.exit_code)


class SearchsploitWorker(QThread):
    done = Signal(object, int)  # (list[ExploitHit], request_id)

    def __init__(self, product: str, version: str, output_file: Path, request_id: int) -> None:
        super().__init__()
        self._product = product
        self._version = version
        self._output_file = output_file
        self._request_id = request_id

    def run(self) -> None:
        try:
            hits = references.search_exploits(self._product, self._version, self._output_file)
        except Exception:  # boundary: never let an EDB lookup crash the worker
            hits = []
        self.done.emit(hits, self._request_id)


@dataclass
class SmbReconResult:
    summary: list[str]
    creds: list[Credential]


class SmbReconWorker(QThread):
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
            out = base / step.command.output_file
            shell.run(step.command.shell_line, out, cwd=base, on_line=self.line.emit)
            if not step.tool:
                continue
            try:
                text = out.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            found.extend(parse_smb_tool(step.tool, text))
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


class FtpReconWorker(QThread):
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
        shell.run(shell_line, out, cwd=base, on_line=self.line.emit)
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
            nmap_text = self._run_step(step.command.shell_line, step.command.output_file)
            if step.tool:
                collected += parse_ftp_tool(step.tool, nmap_text)
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
        listed = 0
        while queue and listed < _FTP_MAX_DIRS:
            path, depth = queue.pop(0)
            if path in seen:
                continue
            seen.add(path)
            step = module.list_step(target, path, self._port)
            text = self._run_step(step.command.shell_line, step.command.output_file)
            listed += 1
            for entry in parse_ftp_listing(text):
                child = path.rstrip("/") + "/" + entry.name
                kind = "dir" if entry.is_dir else "file"
                detail = "" if entry.is_dir else f"{entry.size} bytes"
                findings.append(FtpFinding(kind, child, detail))
                if recurse and entry.is_dir and depth + 1 < _FTP_MAX_DEPTH:
                    queue.append((child + "/", depth + 1))
        if queue:  # exited on the dir cap — say so, don't pretend the walk was exhaustive
            self.line.emit(
                f"[ftp] walk bounded at {_FTP_MAX_DIRS} dirs — list deeper paths via Tier-2"
            )
        return findings

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
        if any(f.kind == "note" and "bounce" in f.value for f in collected):
            summary.append("Note: FTP bounce accepted (recon)")
        summary.append("Anonymous access: allowed" if anon else "Anonymous access: denied")
        return summary


@dataclass
class SshReconResult:
    summary: list[str]


class SshReconWorker(QThread):
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
        shell.run(shell_line, out, cwd=base, on_line=self.line.emit)
        try:
            return out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _drive(self) -> SshReconResult:
        target = self._profile.target
        collected: list[SshFinding] = []
        for step in self._module.recon_steps(target, self._port):
            text = self._run_step(step.command.shell_line, step.command.output_file)
            if step.tool:
                collected += parse_ssh_tool(step.tool, text)
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


class DnsReconWorker(QThread):
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
        shell.run(shell_line, out, cwd=base, on_line=self.line.emit)
        try:
            return out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _drive(self) -> DnsReconResult:
        target = self._profile.target
        collected: list[DnsFinding] = []
        for step in self._module.recon_steps(target, self._domain or None, self._port):
            text = self._run_step(step.command.shell_line, step.command.output_file)
            if step.tool:
                collected += parse_dns_tool(step.tool, text)
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


class LdapReconWorker(QThread):
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
        shell.run(shell_line, out, cwd=base, on_line=self.line.emit)
        try:
            return out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _drive(self) -> LdapReconResult:
        target = self._profile.target
        module = self._module
        collected: list[LdapFinding] = []

        for step in module.rootdse_steps(target, self._port):
            text = self._run_step(step.command.shell_line, step.command.output_file)
            if step.tool:
                collected += parse_ldap_tool(step.tool, text)

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
                collected += parse_ldap_tool(user_step.tool, text)

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


@dataclass
class SimpleReconResult:
    module: str
    summary: list[str]


class SimpleReconWorker(QThread):
    line = Signal(str)
    done = Signal(object)  # SimpleReconResult
    failed = Signal(str)

    def __init__(self, profile: Profile, module_name: str) -> None:
        super().__init__()
        self._profile = profile
        self._spec = SIMPLE_SPECS[module_name]

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
        shell.run(shell_line, out, cwd=base, on_line=self.line.emit)
        try:
            return out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _drive(self) -> SimpleReconResult:
        target = self._profile.target
        raw: dict[str, str] = {}
        for command, tool in self._spec.steps_fn(target):
            text = self._run_step(command.shell_line, command.output_file)
            if tool:  # unparsed steps (e.g. tftp GETs) still run, but carry no parser key
                raw[tool] = text
        module = self._spec.factory()
        found = module.parse(raw)
        self._write_findings(found)
        return SimpleReconResult(self._spec.module, self._summarize(module, found))

    def _write_findings(self, found: list[Finding]) -> None:
        if not found:
            return
        now = datetime.now(UTC).isoformat()
        findings.add_findings(
            self._profile.directory,
            [
                {
                    "module": f.service,
                    "kind": f.fields.get("kind", ""),
                    "value": f.fields.get("value", ""),
                    "detail": f.detail,
                    "discovered_at": now,
                }
                for f in found
            ],
        )

    def _summarize(self, module: Module, found: list[Finding]) -> list[str]:
        summary: list[str] = []
        by_kind: dict[str, list[str]] = {}
        for f in found:
            by_kind.setdefault(f.fields.get("kind", "?"), []).append(f.fields.get("value", ""))
        for kind, values in by_kind.items():
            shown = ", ".join(v for v in values[:4] if v)
            more = " …" if len(values) > 4 else ""
            summary.append(f"{kind} ({len(values)}): {shown}{more}")
        summary.extend(f"→ {tip}" for tip in module.suggest(found))
        return summary or [f"No {self._spec.module.upper()} findings."]


def _app_version() -> str:
    try:
        return metadata.version("oscp-recon")
    except metadata.PackageNotFoundError:
        return "0.0.1"


def _slug(command: str) -> str:
    tokens = command.split()
    base = tokens[0] if tokens else "command"
    return re.sub(r"[^A-Za-z0-9._-]", "-", base) or "command"


def _contained_path(base: Path, rel: str) -> Path | None:
    # why: the http Output field is user-editable — an absolute or ../ value would let a tool write
    # outside the profile. Refuse anything that does not resolve inside the profile directory.
    if Path(rel).is_absolute():
        return None
    candidate = (base / rel).resolve()
    if not candidate.is_relative_to(base.resolve()):
        return None
    return candidate


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("oscp-recon")
        self.resize(1200, 720)
        self._profile: Profile | None = None
        self._worker: QThread | None = None
        self._recent_menu: QMenu
        self._new_action: QAction
        self._open_action: QAction
        self._save_action: QAction

        self._target_label = QLabel("No profile loaded.")
        self._run_button = QPushButton("Run Full Recon")
        self._run_button.setEnabled(False)
        self._run_button.clicked.connect(self._on_run)

        self._service_tree = ServiceTree()
        self._service_tree.service_selected.connect(self._on_service_selected)
        self._service_tree.treat_as_http.connect(self._on_treat_as_http)
        self._tool_panel = ToolPanel()
        self._tool_panel.run_requested.connect(self._on_run_command)
        self._tool_panel.http_run_requested.connect(self._on_http_run)
        self._tool_panel.http_dry_run_requested.connect(self._on_http_dry_run)
        self._tool_panel.http_add_report_requested.connect(self._on_http_add_report)
        self._tool_panel.vhost_run_requested.connect(self._on_vhost_run)
        self._tool_panel.vhost_dry_run_requested.connect(self._on_http_dry_run)
        self._tool_panel.wildcard_detect_requested.connect(self._on_wildcard_detect)
        self._tool_panel.enumerate_as_http_requested.connect(self._on_enumerate_as_http)
        self._tool_panel.smb_recon_requested.connect(self._on_smb_recon)
        self._tool_panel.ftp_recon_requested.connect(self._on_ftp_recon)
        self._tool_panel.ssh_recon_requested.connect(self._on_ssh_recon)
        self._tool_panel.dns_recon_requested.connect(self._on_dns_recon)
        self._tool_panel.ldap_recon_requested.connect(self._on_ldap_recon)
        self._tool_panel.simple_recon_requested.connect(self._on_simple_recon)
        self._tool_panel.vhost_validation_failed.connect(
            lambda msg: self._tool_panel.append_output(f"[blocked] {msg}")
        )
        self._reference_pane = ReferencePane()
        self._reference_pane.page_visited.connect(self._on_page_visited)
        self._edb_request_id = 0
        self._edb_workers: set[QThread] = set()
        self._pending_visits: list[tuple[str, str]] = []
        self._http_parse: tuple[Path, str, int] | None = None
        self._vhost_parse: tuple[Path, str, str] | None = None
        self._wildcard_out: Path | None = None
        self._treat_http_ctx: DiscoveredService | None = None

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.addWidget(self._target_label)
        left_layout.addWidget(self._run_button)
        left_layout.addWidget(self._service_tree, stretch=1)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left)
        splitter.addWidget(self._tool_panel)
        splitter.addWidget(self._reference_pane)
        splitter.setSizes([320, 520, 360])
        self.setCentralWidget(splitter)

        self._notes_pane = NotesPane()
        self._notes_dock = QDockWidget("Notes", self)
        self._notes_dock.setWidget(self._notes_pane)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._notes_dock)

        # status footer (§19): app+version · active profile · workspace · exam-legal reminder
        self._status_profile = QLabel()
        self._status_workspace = QLabel()
        legal = QLabel("recon-only — OSCP exam legal per CLAUDE.md §2")
        legal.setStyleSheet("color: gray;")
        status = self.statusBar()
        assert status is not None
        status.addWidget(QLabel(f"oscp-recon v{_app_version()}"))
        status.addWidget(self._status_profile)
        status.addWidget(self._status_workspace)
        status.addPermanentWidget(legal)
        self._update_status_footer()

        self._build_menus()
        self._load_last_profile()

    def _update_status_footer(self) -> None:
        name = self._profile.profile_name if self._profile is not None else "no profile loaded"
        self._status_profile.setText(f"profile: {name}")
        self._status_workspace.setText(f"workspace: {config.workspace_root()}")

    def _build_menus(self) -> None:
        file_menu = self.menuBar().addMenu("&File")

        self._new_action = QAction("New Scan Profile...", self)
        self._new_action.setShortcut("Ctrl+N")
        self._new_action.triggered.connect(self._on_new)
        file_menu.addAction(self._new_action)

        self._open_action = QAction("Open Scan Profile...", self)
        self._open_action.setShortcut("Ctrl+O")
        self._open_action.triggered.connect(self._on_open)
        file_menu.addAction(self._open_action)

        self._recent_menu = file_menu.addMenu("Recent Profiles")
        self._rebuild_recent_menu()

        file_menu.addSeparator()
        self._save_action = QAction("Save", self)
        self._save_action.setShortcut("Ctrl+S")
        self._save_action.triggered.connect(self._on_save)
        file_menu.addAction(self._save_action)

        file_menu.addSeparator()
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        scan_menu = self.menuBar().addMenu("&Scan")
        run_action = QAction("Run Full Recon", self)
        run_action.triggered.connect(self._on_run)
        scan_menu.addAction(run_action)

        edit_menu = self.menuBar().addMenu("&Edit")
        add_cred_action = QAction("Add Credential...", self)
        add_cred_action.triggered.connect(self._on_add_credential)
        edit_menu.addAction(add_cred_action)

        view_menu = self.menuBar().addMenu("&View")
        view_menu.addAction(self._notes_dock.toggleViewAction())
        wordlists_action = QAction("Browse Wordlists...", self)
        wordlists_action.triggered.connect(self._on_browse_wordlists)
        view_menu.addAction(wordlists_action)

    def _rebuild_recent_menu(self) -> None:
        self._recent_menu.clear()
        recents = config.recent_profiles()
        if not recents:
            empty = QAction("(none)", self)
            empty.setEnabled(False)
            self._recent_menu.addAction(empty)
            return
        for path in recents:
            action = QAction(path, self)
            action.triggered.connect(
                lambda _checked=False, target=path: self._open_path(Path(target))
            )
            self._recent_menu.addAction(action)

    def _set_profile(self, profile: Profile) -> None:
        self._profile = profile
        target = profile.target
        label = f"{profile.profile_name} — {target.ip}"
        if target.hostname:
            label += f" ({target.hostname})"
        self._target_label.setText(label)
        self.setWindowTitle(f"oscp-recon — {profile.profile_name}")
        self._run_button.setEnabled(True)
        self._tool_panel.set_target(target.ip)
        self._tool_panel.set_profile(profile)
        self._service_tree.populate(profile.discovered_services)
        self._update_status_footer()
        self._notes_pane.set_profile(profile)
        config.add_recent(profile.directory)
        self._rebuild_recent_menu()

    @staticmethod
    def _safe_load(path: Path) -> Profile | None:
        try:
            return Profile.load(path)
        except (OSError, ValueError, KeyError):
            return None

    def _load_last_profile(self) -> None:
        for path in config.recent_profiles():
            candidate = Path(path)
            if not (candidate / "profile.json").exists():
                continue
            profile = self._safe_load(candidate)
            if profile is None:
                self._tool_panel.append_output(f"[skipped corrupt] {candidate}")
                continue
            self._set_profile(profile)
            self._tool_panel.append_output(f"[restored] {candidate}")
            return

    def _on_service_selected(self, service: object) -> None:
        selected = service if isinstance(service, DiscoveredService) else None
        ref = references.match(selected) if selected is not None else None
        self._tool_panel.show_service(selected, ref)
        self._reference_pane.show_service(selected, ref)
        self._edb_request_id += 1
        if selected is None or not selected.product or self._profile is None:
            return
        output_file = (
            self._profile.directory
            / "references"
            / f"edb-{selected.port}-{selected.proto.value}.json"
        )
        worker = SearchsploitWorker(
            selected.product, selected.version, output_file, self._edb_request_id
        )
        worker.done.connect(self._on_edb_done)
        worker.finished.connect(lambda w=worker: self._edb_workers.discard(w))
        self._edb_workers.add(worker)
        worker.start()

    def _on_edb_done(self, hits: object, request_id: int) -> None:
        if request_id != self._edb_request_id:
            return  # a newer selection superseded this lookup
        if isinstance(hits, list):
            self._reference_pane.show_exploits(hits)

    def _on_page_visited(self, label: str, url: str) -> None:
        if self._profile is None:
            return
        if self._worker is not None:
            # why: a worker is saving profile.json on its thread — buffer the visit and persist it
            # in _finish_worker rather than dropping it or racing the save.
            self._pending_visits.append((label, url))
            return
        self._profile.add_reference_visited(label, url)
        self._profile.save()

    def _on_new(self) -> None:
        dialog = NewProfileDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        name, ip = dialog.values()
        if not name or not ip:
            QMessageBox.warning(
                self, "Missing input", "Both a profile name and a target are required."
            )
            return
        try:
            profile = Profile.create(config.workspace_root(), name, Target(ip=ip))
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid target", str(exc))
            return
        self._tool_panel.clear_output()
        self._set_profile(profile)
        self._tool_panel.append_output(f"[created] {profile.directory}")

    def _on_open(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self, "Open Scan Profile", str(config.workspace_root())
        )
        if chosen:
            self._open_path(Path(chosen))

    def _open_path(self, path: Path) -> None:
        if not (path / "profile.json").exists():
            QMessageBox.warning(self, "Not a profile", f"{path} has no profile.json.")
            return
        profile = self._safe_load(path)
        if profile is None:
            QMessageBox.warning(self, "Corrupt profile", f"{path}/profile.json could not be read.")
            return
        self._tool_panel.clear_output()
        self._set_profile(profile)
        self._tool_panel.append_output(f"[opened] {path}")

    def _on_save(self) -> None:
        if self._profile is not None:
            self._notes_pane.flush()
            self._profile.save()
            self._tool_panel.append_output("[saved]")

    def _on_add_credential(self) -> None:
        if self._profile is None:
            QMessageBox.information(self, "No profile", "Open or create a profile first.")
            return
        dialog = AddCredentialDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        cred = dialog.credential()
        if cred is None:
            QMessageBox.warning(self, "Missing fields", "Username and secret are required.")
            return
        self._profile.add_credential(cred)
        self._tool_panel.append_output(f"[cred] added {cred.username} (source: {cred.source})")

    def _on_browse_wordlists(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("Wordlists")
        dialog.resize(640, 460)
        picker = WordlistPicker()
        layout = QVBoxLayout(dialog)
        layout.addWidget(picker)
        try:
            dialog.exec()
        finally:
            picker.shutdown()  # wait the index worker before the widget is destroyed

    def _set_busy(self, busy: bool) -> None:
        # why: the worker thread mutates and saves the shared Profile; locking these entry points
        # prevents a concurrent save from racing profile.json and a second overlapping run.
        self._new_action.setEnabled(not busy)
        self._open_action.setEnabled(not busy)
        self._save_action.setEnabled(not busy)
        self._recent_menu.setEnabled(not busy)
        self._service_tree.setEnabled(not busy)
        self._run_button.setEnabled(not busy and self._profile is not None)
        self._tool_panel.set_running(busy)

    def closeEvent(self, event: QCloseEvent) -> None:
        # why: destroying the window while the QThread runs aborts the process and can truncate
        # profile.json — wait for the in-flight run to finish first.
        self._notes_pane.flush()
        if self._worker is not None and self._worker.isRunning():
            self._worker.wait()
        for edb_worker in list(self._edb_workers):
            if edb_worker.isRunning():
                edb_worker.wait()
        super().closeEvent(event)

    def _on_run(self) -> None:
        if self._profile is None or self._worker is not None:
            return
        self._set_busy(True)
        self._tool_panel.append_output("[nmap] starting…")
        worker = NmapWorker(self._profile)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_scan_done)
        worker.failed.connect(self._on_run_failed)
        self._worker = worker
        worker.start()

    def _on_run_command(self, command: str) -> None:
        if self._profile is None or self._worker is not None:
            return
        manual_dir = self._profile.directory / "manual"
        manual_dir.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha1(command.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]
        output_file = manual_dir / f"{_slug(command)}-{digest}.txt"
        with (manual_dir / "commands.txt").open("a", encoding="utf-8") as history:
            history.write(command + "\n")
        self._set_busy(True)
        self._tool_panel.append_output(f"$ {command}")
        worker = CommandWorker(command, output_file, cwd=self._profile.directory)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_command_done)
        worker.failed.connect(self._on_run_failed)
        self._worker = worker
        worker.start()

    def _on_http_run(self, command: str, output_rel: str, tool: str, port: int) -> None:
        if self._profile is None or self._worker is not None or not output_rel:
            return
        struct_path = _contained_path(self._profile.directory, output_rel)
        if struct_path is None:
            self._tool_panel.append_output(
                f"[blocked] output path must stay inside the profile: {output_rel}"
            )
            return
        struct_path.parent.mkdir(parents=True, exist_ok=True)
        self._http_parse = (struct_path, tool, port)
        self._set_busy(True)
        self._tool_panel.append_output(f"$ {command}")
        worker = CommandWorker(
            command, struct_path.with_suffix(".log"), cwd=self._profile.directory
        )
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_command_done)
        worker.failed.connect(self._on_run_failed)
        self._worker = worker
        worker.start()

    def _on_http_dry_run(self, command: str) -> None:
        self._tool_panel.append_output(f"[dry-run] {command}")

    def _on_http_add_report(self, command: str) -> None:
        if self._profile is None:
            return
        manual_dir = self._profile.directory / "manual"
        manual_dir.mkdir(parents=True, exist_ok=True)
        with (manual_dir / "commands.txt").open("a", encoding="utf-8") as history:
            history.write(command + "\n")
        self._tool_panel.append_output(f"[report] queued: {command}")

    def _parse_http_output(self, struct_path: Path, tool: str, port: int) -> None:
        if self._profile is None:
            return
        try:
            text = struct_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        hits = parse_tool(tool, text, port)
        if hits:
            now = datetime.now(UTC).isoformat()
            findings.add_findings(self._profile.directory, [h.to_dict(now) for h in hits])
            self._tool_panel.append_output(f"[findings] +{len(hits)} from {tool} -> findings.json")
        if detect_wordpress(text):
            self._tool_panel.append_output(
                "[wordpress] detected — follow-up: "
                "wpscan --enumerate vp,vt,tt,cb,dbe,u,m --url <target>"
            )

    def _on_vhost_run(self, command: str, output_rel: str, tool: str, domain: str) -> None:
        if self._profile is None or self._worker is not None or not output_rel:
            return
        struct_path = _contained_path(self._profile.directory, output_rel)
        if struct_path is None:
            self._tool_panel.append_output(
                f"[blocked] output path must stay inside the profile: {output_rel}"
            )
            return
        struct_path.parent.mkdir(parents=True, exist_ok=True)
        # why: clear a stale -o from a prior run so a failed/blocked re-run can't resurrect it
        # (the parser would otherwise read the old file and report old vhosts as new).
        struct_path.unlink(missing_ok=True)
        self._vhost_parse = (struct_path, tool, domain)
        self._set_busy(True)
        self._tool_panel.append_output(f"$ {command}")
        worker = CommandWorker(
            command, struct_path.with_suffix(".log"), cwd=self._profile.directory
        )
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_command_done)
        worker.failed.connect(self._on_run_failed)
        self._worker = worker
        worker.start()

    def _parse_vhost_output(self, struct_path: Path, tool: str, domain: str) -> None:
        if self._profile is None:
            return
        # ffuf/gobuster write -o (struct_path); dnsrecon/wfuzz write stdout (captured to the .log)
        path = struct_path if struct_path.exists() else struct_path.with_suffix(".log")
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        hits = parse_vhost_tool(tool, text, domain)
        if hits:
            now = datetime.now(UTC).isoformat()
            findings.add_findings(self._profile.directory, [h.to_dict(now) for h in hits])
            self._tool_panel.add_vhosts([h.vhost for h in hits])
            self._tool_panel.append_output(f"[vhosts] +{len(hits)} -> findings.json")

    def _on_wildcard_detect(self, command: str, output_rel: str) -> None:
        if self._profile is None or self._worker is not None:
            return
        out = _contained_path(self._profile.directory, output_rel)
        if out is None:
            return
        out.parent.mkdir(parents=True, exist_ok=True)
        self._wildcard_out = out
        self._set_busy(True)
        self._tool_panel.append_output(f"$ {command}")
        worker = CommandWorker(command, out, cwd=self._profile.directory)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_command_done)
        worker.failed.connect(self._on_run_failed)
        self._worker = worker
        worker.start()

    def _apply_wildcard_size(self, out: Path) -> None:
        try:
            text = out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        digits = "".join(c for c in text if c.isdigit())
        if digits:
            self._tool_panel.set_vhost_filter_size(int(digits))
            self._tool_panel.append_output(f"[wildcard] baseline size {digits} -> -fs set")

    def _on_enumerate_as_http(self, vhost: str) -> None:
        self._tool_panel.enumerate_http(vhost)
        self._tool_panel.append_output(f"[http] enumerate vhost as http://{vhost}/")

    def _on_treat_as_http(self, service: object) -> None:
        if (
            not isinstance(service, DiscoveredService)
            or self._profile is None
            or self._worker is not None
        ):
            return
        url = default_url(self._profile.target.ip, service.port, False)
        probe_out = self._profile.directory / "http" / str(service.port) / "probe.txt"
        probe_out.parent.mkdir(parents=True, exist_ok=True)
        self._treat_http_ctx = service
        self._set_busy(True)
        self._tool_panel.append_output(f"[probe] curl -sIk {url}")
        worker = CommandWorker(f"curl -sIk {url}", probe_out, cwd=self._profile.directory)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_probe_done)
        worker.failed.connect(self._on_run_failed)
        self._worker = worker
        worker.start()

    def _on_probe_done(self, exit_code: int) -> None:
        service = self._treat_http_ctx
        self._treat_http_ctx = None
        if exit_code == 0 and service is not None and self._profile is not None:
            for discovered in self._profile.discovered_services:
                if discovered.port == service.port and discovered.proto == service.proto:
                    discovered.service = "http"
            self._profile.save()
            self._tool_panel.append_output(f"[http] port {service.port} now treated as HTTP")
        else:
            self._tool_panel.append_output("[probe] no HTTP response")
        self._finish_worker()

    def _on_smb_recon(self, mode: str) -> None:
        if self._profile is None or self._worker is not None:
            return
        self._set_busy(True)
        self._tool_panel.append_output(f"[smb] {mode} recon starting…")
        worker = SmbReconWorker(self._profile, mode)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_smb_done)
        worker.failed.connect(self._on_run_failed)
        self._worker = worker
        worker.start()

    def _on_smb_done(self, result: object) -> None:
        # why: a creds.json/summary write error must not strand self._worker — always release the
        # slot in _finish_worker, mirroring _on_command_done's guard.
        try:
            if isinstance(result, SmbReconResult) and self._profile is not None:
                for cred in result.creds:
                    self._profile.add_credential(cred)
                    self._tool_panel.append_output(
                        f"[cred] {cred.username} (source: {cred.source})"
                    )
                self._tool_panel.set_smb_summary(result.summary)
                self._tool_panel.append_output("[smb] recon complete")
        except Exception as exc:  # boundary: never wedge the worker slot on a UI-thread write error
            self._tool_panel.append_output(f"[error] {exc}")
        self._finish_worker()

    def _on_ftp_recon(self, mode: str, port: int) -> None:
        if self._profile is None or self._worker is not None:
            return
        self._set_busy(True)
        self._tool_panel.append_output(f"[ftp] {mode} recon on port {port} starting…")
        worker = FtpReconWorker(self._profile, mode, port)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_ftp_done)
        worker.failed.connect(self._on_run_failed)
        self._worker = worker
        worker.start()

    def _on_ftp_done(self, result: object) -> None:
        # why: a creds.json/summary write error must not strand self._worker — always release the
        # slot in _finish_worker, mirroring _on_command_done's guard.
        try:
            if isinstance(result, FtpReconResult) and self._profile is not None:
                for cred in result.creds:
                    self._profile.add_credential(cred)
                    self._tool_panel.append_output(
                        f"[cred] {cred.username} (source: {cred.source})"
                    )
                self._tool_panel.set_ftp_summary(result.summary)
                self._tool_panel.append_output("[ftp] recon complete")
        except Exception as exc:  # boundary: never wedge the worker slot on a UI-thread write error
            self._tool_panel.append_output(f"[error] {exc}")
        self._finish_worker()

    def _on_ssh_recon(self, port: int) -> None:
        if self._profile is None or self._worker is not None:
            return
        self._set_busy(True)
        self._tool_panel.append_output(f"[ssh] recon on port {port} starting…")
        worker = SshReconWorker(self._profile, port)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_ssh_done)
        worker.failed.connect(self._on_run_failed)
        self._worker = worker
        worker.start()

    def _on_ssh_done(self, result: object) -> None:
        # why: a summary write error must not strand self._worker — always release the slot in
        # _finish_worker, mirroring _on_ftp_done's guard.
        try:
            if isinstance(result, SshReconResult):
                self._tool_panel.set_ssh_summary(result.summary)
                self._tool_panel.append_output("[ssh] recon complete")
        except Exception as exc:  # boundary: never wedge the worker slot on a UI-thread write error
            self._tool_panel.append_output(f"[error] {exc}")
        self._finish_worker()

    def _on_simple_recon(self, module_name: str) -> None:
        if self._profile is None or self._worker is not None or module_name not in SIMPLE_SPECS:
            return
        self._set_busy(True)
        self._tool_panel.append_output(f"[{module_name}] recon starting…")
        worker = SimpleReconWorker(self._profile, module_name)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_simple_done)
        worker.failed.connect(self._on_run_failed)
        self._worker = worker
        worker.start()

    def _on_simple_done(self, result: object) -> None:
        # why: a summary write error must not strand self._worker — always release the slot in
        # _finish_worker, mirroring _on_ssh_done's guard.
        try:
            if isinstance(result, SimpleReconResult):
                self._tool_panel.set_simple_summary(result.module, result.summary)
                self._tool_panel.append_output(f"[{result.module}] recon complete")
        except Exception as exc:  # boundary: never wedge the worker slot on a UI-thread write error
            self._tool_panel.append_output(f"[error] {exc}")
        self._finish_worker()

    def _on_dns_recon(self, domain: str, port: int) -> None:
        if self._profile is None or self._worker is not None:
            return
        self._set_busy(True)
        scope = f"zone {domain}" if domain else "no zone (version + recursion only)"
        self._tool_panel.append_output(f"[dns] recon on port {port} — {scope} starting…")
        worker = DnsReconWorker(self._profile, domain, port)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_dns_done)
        worker.failed.connect(self._on_run_failed)
        self._worker = worker
        worker.start()

    def _on_dns_done(self, result: object) -> None:
        # why: a summary write error must not strand self._worker — always release the slot in
        # _finish_worker, mirroring _on_ssh_done's guard.
        try:
            if isinstance(result, DnsReconResult):
                self._tool_panel.set_dns_summary(result.summary)
                self._tool_panel.append_output("[dns] recon complete")
        except Exception as exc:  # boundary: never wedge the worker slot on a UI-thread write error
            self._tool_panel.append_output(f"[error] {exc}")
        self._finish_worker()

    def _on_ldap_recon(self, basedn: str, port: int) -> None:
        if self._profile is None or self._worker is not None:
            return
        self._set_busy(True)
        scope = f"base {basedn}" if basedn else "auto-discover base DN"
        self._tool_panel.append_output(f"[ldap] recon on port {port} — {scope} starting…")
        worker = LdapReconWorker(self._profile, basedn, port)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_ldap_done)
        worker.failed.connect(self._on_run_failed)
        self._worker = worker
        worker.start()

    def _on_ldap_done(self, result: object) -> None:
        # why: a creds/summary write error must not strand self._worker — always release the slot in
        # _finish_worker, mirroring _on_smb_done / _on_ftp_done.
        try:
            if isinstance(result, LdapReconResult) and self._profile is not None:
                for cred in result.creds:
                    self._profile.add_credential(cred)
                    self._tool_panel.append_output(
                        f"[cred] {cred.username} (source: {cred.source})"
                    )
                self._tool_panel.set_ldap_summary(result.summary)
                self._tool_panel.append_output("[ldap] recon complete")
        except Exception as exc:  # boundary: never wedge the worker slot on a UI-thread write error
            self._tool_panel.append_output(f"[error] {exc}")
        self._finish_worker()

    def _on_scan_done(self, count: int) -> None:
        self._tool_panel.append_output(f"[nmap] done — {count} services")
        self._finish_worker()

    def _on_command_done(self, exit_code: int) -> None:
        self._tool_panel.append_output(f"[done] exit={exit_code}")
        try:
            if self._http_parse is not None:
                struct_path, tool, port = self._http_parse
                self._http_parse = None
                self._parse_http_output(struct_path, tool, port)
            elif self._vhost_parse is not None:
                vstruct, vtool, domain = self._vhost_parse
                self._vhost_parse = None
                self._parse_vhost_output(vstruct, vtool, domain)
            elif self._wildcard_out is not None:
                out = self._wildcard_out
                self._wildcard_out = None
                self._apply_wildcard_size(out)
        except Exception as exc:  # boundary: any parse/write error must not wedge the worker slot
            self._tool_panel.append_output(f"[parse] failed: {exc}")
        self._finish_worker()

    def _on_run_failed(self, message: str) -> None:
        self._tool_panel.append_output(f"[error] {message}")
        self._http_parse = None
        self._vhost_parse = None
        self._wildcard_out = None
        self._treat_http_ctx = None
        self._finish_worker()

    def _finish_worker(self) -> None:
        if self._worker is not None:
            self._worker.wait()
            self._worker = None
        if self._profile is not None:
            if self._pending_visits:
                for label, url in self._pending_visits:
                    self._profile.add_reference_visited(label, url)
                self._pending_visits.clear()
                self._profile.save()
            self._set_profile(self._profile)
        self._set_busy(False)
