from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
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
from oscprecon.gui.widgets.notes_pane import NotesPane
from oscprecon.gui.widgets.reference_pane import ReferencePane
from oscprecon.gui.widgets.service_tree import ServiceTree
from oscprecon.gui.widgets.tool_panel import ToolPanel
from oscprecon.gui.widgets.wordlist_picker import WordlistPicker
from oscprecon.models import Credential, DiscoveredService, Target
from oscprecon.modules.http import default_url, detect_wordpress, parse_tool
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

        self._build_menus()
        self._load_last_profile()

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
