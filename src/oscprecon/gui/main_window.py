from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QThread
from PySide6.QtGui import QAction, QActionGroup, QCloseEvent
from PySide6.QtWidgets import (
    QDialog,
    QDockWidget,
    QFileDialog,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from oscprecon import config, findings, references, vault_export
from oscprecon.audit import Auditor
from oscprecon.gui import theme
from oscprecon.gui.dialogs import AddCredentialDialog, NewProfileDialog
from oscprecon.gui.simple_recon import SIMPLE_SPECS
from oscprecon.gui.task_manager import TaskManager
from oscprecon.gui.widgets.graph_view import GraphView
from oscprecon.gui.widgets.notes_pane import NotesPane
from oscprecon.gui.widgets.reference_pane import ReferencePane
from oscprecon.gui.widgets.report_view import ReportView
from oscprecon.gui.widgets.service_tree import ServiceTree
from oscprecon.gui.widgets.task_status_bar import TaskStatusBar
from oscprecon.gui.widgets.tool_panel import ToolPanel
from oscprecon.gui.widgets.wordlist_picker import WordlistPicker
from oscprecon.gui.workers import (
    CancellableThread,
    CommandWorker,
    DnsReconResult,
    DnsReconWorker,
    FtpReconResult,
    FtpReconWorker,
    LdapReconResult,
    LdapReconWorker,
    NmapWorker,
    SearchsploitWorker,
    SimpleReconResult,
    SimpleReconWorker,
    SmbReconResult,
    SmbReconWorker,
    SshReconResult,
    SshReconWorker,
)
from oscprecon.manual_commands import expand, load_manual_commands
from oscprecon.models import DiscoveredService, Target
from oscprecon.modules.http import default_url, detect_wordpress, parse_tool
from oscprecon.modules.vhost import parse_vhost_tool
from oscprecon.patterns.engine import suggest_for
from oscprecon.profile import Profile

# Workers moved to oscprecon.gui.workers; re-exported here so existing imports/tests keep working.
__all__ = [
    "AddCredentialDialog",
    "CancellableThread",
    "CommandWorker",
    "DnsReconResult",
    "DnsReconWorker",
    "FtpReconResult",
    "FtpReconWorker",
    "LdapReconResult",
    "LdapReconWorker",
    "MainWindow",
    "NewProfileDialog",
    "NmapWorker",
    "SearchsploitWorker",
    "SimpleReconResult",
    "SimpleReconWorker",
    "SmbReconResult",
    "SmbReconWorker",
    "SshReconResult",
    "SshReconWorker",
]


def _app_version() -> str:
    try:
        return metadata.version("oscp-recon")
    except metadata.PackageNotFoundError:
        return "0.0.1"


def _slug(command: str) -> str:
    tokens = command.split()
    base = tokens[0] if tokens else "command"
    return re.sub(r"[^A-Za-z0-9._-]", "-", base) or "command"


_SCAN_PRESETS = Path(__file__).parent.parent / "references" / "scan_presets.yaml"


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
        theme.apply_theme(config.load_prefs().get("theme", theme.DEFAULT_THEME))
        self.setWindowTitle("oscp-recon")
        self.resize(1200, 720)
        self._profile: Profile | None = None
        self._auditor: Auditor | None = None
        self._tasks = TaskManager()
        self._task_bar = TaskStatusBar(self._tasks)
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

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.addWidget(self._target_label)
        left_layout.addWidget(self._run_button)
        left_layout.addWidget(self._task_bar)
        left_layout.addWidget(self._service_tree, stretch=1)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left)
        splitter.addWidget(self._tool_panel)
        splitter.addWidget(self._reference_pane)
        splitter.setSizes([320, 520, 360])

        self._graph_view = GraphView()
        self._graph_view.service_open_requested.connect(self._on_graph_service_open)
        self._report_view = ReportView()
        self._central_stack = QStackedWidget()
        self._central_stack.addWidget(splitter)  # 0: three-pane
        self._central_stack.addWidget(self._graph_view)  # 1: graph
        self._central_stack.addWidget(self._report_view)  # 2: report preview
        self.setCentralWidget(self._central_stack)

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

        self._export_vault_action = QAction("Export to Obsidian Vault...", self)
        self._export_vault_action.triggered.connect(self._on_export_vault)
        file_menu.addAction(self._export_vault_action)

        file_menu.addSeparator()
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        scan_menu = self.menuBar().addMenu("&Scan")
        run_action = QAction("Run Full Recon", self)
        run_action.triggered.connect(self._on_run)
        scan_menu.addAction(run_action)

        presets_menu = scan_menu.addMenu("Nmap presets")
        for preset in load_manual_commands(_SCAN_PRESETS):
            action = QAction(preset.description, self)
            action.setToolTip(preset.why)
            action.triggered.connect(
                lambda _checked=False, cmd=preset.command: self._on_scan_preset(cmd)
            )
            presets_menu.addAction(action)

        edit_menu = self.menuBar().addMenu("&Edit")
        add_cred_action = QAction("Add Credential...", self)
        add_cred_action.triggered.connect(self._on_add_credential)
        edit_menu.addAction(add_cred_action)

        view_menu = self.menuBar().addMenu("&View")
        view_menu.addAction(self._notes_dock.toggleViewAction())
        self._graph_action = QAction("Graph", self)
        self._graph_action.setCheckable(True)
        self._graph_action.setShortcut("Ctrl+G")
        self._graph_action.toggled.connect(self._on_toggle_graph)
        view_menu.addAction(self._graph_action)
        self._report_action = QAction("Report Preview", self)
        self._report_action.setCheckable(True)
        self._report_action.setShortcut("Ctrl+R")
        self._report_action.toggled.connect(self._on_toggle_report)
        view_menu.addAction(self._report_action)

        theme_menu = view_menu.addMenu("Theme")
        self._theme_group = QActionGroup(self)
        current_theme = theme.normalize(config.load_prefs().get("theme", theme.DEFAULT_THEME))
        for name in theme.THEMES:
            action = QAction(name.capitalize(), self, checkable=True)
            action.setChecked(name == current_theme)
            action.triggered.connect(lambda _checked=False, n=name: self._set_theme(n))
            self._theme_group.addAction(action)
            theme_menu.addAction(action)

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

    def _audit_action(self, action: str, **details: Any) -> None:
        if self._auditor is not None:
            self._auditor.record(action, details=details)

    def _set_profile(self, profile: Profile) -> None:
        self._profile = profile
        self._auditor = Auditor(profile.directory, profile.profile_name)
        target = profile.target
        label = f"{profile.profile_name} — {target.ip}"
        if target.hostname:
            label += f" ({target.hostname})"
        self._target_label.setText(label)
        self.setWindowTitle(f"oscp-recon — {profile.profile_name}")
        self._tool_panel.set_target(target.ip)
        self._tool_panel.set_profile(profile)
        self._service_tree.populate(profile.discovered_services, force=True)
        self._graph_view.set_profile(profile)
        self._report_view.set_profile(profile)
        self._update_status_footer()
        self._refresh_suggestions()
        self._notes_pane.set_profile(profile)
        config.add_recent(profile.directory)
        self._rebuild_recent_menu()
        self._refresh_busy()

    def _refresh_suggestions(self) -> None:
        # pattern-library "Recon next steps" — recomputed on profile open + after every recon run
        # (via _post_run_refresh -> _set_profile). Never auto-runs anything.
        if self._profile is None:
            self._tool_panel.set_suggestions([])
            return
        self._tool_panel.set_suggestions(
            suggest_for(
                findings.load_findings(self._profile.directory),
                target=self._profile.target.ip,
                domain=self._profile.target.hostname or "",
                has_credential=bool(self._profile.credentials()),
            )
        )

    def _on_toggle_graph(self, checked: bool) -> None:
        if checked:
            self._report_action.setChecked(False)  # graph and report are mutually exclusive views
            self._graph_view.reload()  # refresh from the latest findings/creds/graph.json
        self._central_stack.setCurrentIndex(1 if checked else 0)

    def _on_toggle_report(self, checked: bool) -> None:
        if checked:
            self._graph_action.setChecked(False)
            self._report_view.reload()  # render the current report.md
        self._central_stack.setCurrentIndex(2 if checked else 0)

    def _set_theme(self, name: str) -> None:
        theme.apply_theme(name)
        prefs = config.load_prefs()
        prefs["theme"] = theme.normalize(name)
        config.save_prefs(prefs)

    def _on_graph_service_open(self, port: int, proto: str) -> None:
        # the graph's "Open service tooling" button jumps to the three-pane view + selects the svc
        services = self._profile.discovered_services if self._profile is not None else []
        for svc in services:
            if svc.port == port and svc.proto.value == proto:
                self._graph_action.setChecked(False)
                self._on_service_selected(svc)
                return

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
        if self._tasks.active_count > 0:
            # why: a worker may be saving profile.json on its thread — buffer the visit and persist
            # it in _post_run_refresh rather than dropping it or racing the save.
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
        self._audit_action("profile-created", target=profile.target.ip)
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
        self._audit_action("profile-opened")
        self._tool_panel.append_output(f"[opened] {path}")

    def _on_save(self) -> None:
        if self._profile is not None:
            self._notes_pane.flush()
            self._profile.save()
            self._audit_action("profile-saved")
            self._tool_panel.append_output("[saved]")

    def _on_export_vault(self) -> None:
        if self._profile is None:
            QMessageBox.warning(self, "No profile", "Open or create a profile first.")
            return
        chosen = QFileDialog.getExistingDirectory(
            self, "Export to Obsidian Vault", str(config.workspace_root())
        )
        if not chosen:
            return
        # why: flush the in-editor notes and persist findings/creds so the snapshot is current.
        self._notes_pane.flush()
        self._profile.save()
        out = vault_export.export_vault(self._profile, Path(chosen))
        self._audit_action("profile-exported", dest=str(out))
        self._tool_panel.append_output(f"[exported] {out}")
        QMessageBox.information(
            self,
            "Vault exported",
            f"Snapshot written to:\n{out}\n\nThis is a point-in-time copy (re-export to refresh). "
            "Credential secret values are redacted.",
        )

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
        # why: §6a — log field names + source only; the audit engine never writes the secret value.
        self._audit_action(
            "credential-added",
            username=cred.username,
            domain=cred.domain,
            secret_type=cred.secret_type,
            source=cred.source,
        )
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

    def _refresh_busy(self) -> None:
        # why: profile-lifecycle actions (New/Open/Save) replace the shared Profile, so they lock
        # while ANY task runs. Launching new recon is gated by the bound: the Run button (full nmap)
        # needs an all-clear (it mutates the profile from its thread); parallel service recon just
        # needs room under the concurrency cap.
        any_running = self._tasks.active_count > 0
        self._new_action.setEnabled(not any_running)
        self._open_action.setEnabled(not any_running)
        self._save_action.setEnabled(not any_running)
        self._recent_menu.setEnabled(not any_running)
        self._run_button.setEnabled(
            self._profile is not None and self._tasks.can_start(exclusive=True)
        )
        # why: keep the tree browseable (selecting a service is read-only) — only the launch
        # buttons in the tool panel are gated on capacity, via set_running.
        self._service_tree.setEnabled(self._profile is not None)
        self._tool_panel.set_running(not self._tasks.can_start())

    def _launch(self, worker: QThread, label: str, *, exclusive: bool = False) -> None:
        self._tasks.add(worker, label, exclusive=exclusive)
        worker.finished.connect(lambda: self._release(worker))
        self._audit_action("run", label=label, exclusive=exclusive)
        self._refresh_busy()
        worker.start()

    def _release(self, worker: QThread) -> None:
        worker.wait()  # finished has fired — returns immediately
        label = next((task.label for task in self._tasks.tasks() if task.worker is worker), "")
        self._tasks.remove(worker)
        worker.deleteLater()
        self._audit_action("run-finished", label=label)
        self._post_run_refresh()

    def _post_run_refresh(self) -> None:
        # why: this fires on EVERY worker completion (up to 4 in parallel). Refresh only what a
        # background run can change — services tree, graph, suggestions, status — and never reload
        # the notes editor / command builder / window title / recent menu (that churns the user's
        # context mid-work). The tree/notes widgets are idempotent, so an unchanged set is a no-op.
        if self._profile is not None:
            if self._pending_visits:
                for label, url in self._pending_visits:
                    self._profile.add_reference_visited(label, url)
                self._pending_visits.clear()
                self._profile.save()
            self._service_tree.populate(self._profile.discovered_services)
            self._graph_view.set_profile(self._profile)
            self._refresh_suggestions()
            self._update_status_footer()
            if self._central_stack.currentIndex() == 2:
                self._report_view.reload()  # live-refresh the report if it's the visible view
        self._refresh_busy()

    def closeEvent(self, event: QCloseEvent) -> None:
        # why: destroying the window while a QThread runs aborts the process and can truncate
        # profile.json — so we wait for every in-flight task. But wait() on the GUI thread with no
        # prior cancel freezes the window for the tool's full remaining runtime; cancel first so
        # shell.run kills the child group and each worker returns promptly, then wait to tear down.
        self._notes_pane.flush()
        self._audit_action("profile-closed")
        self._tasks.cancel_all()
        for edb_worker in list(self._edb_workers):
            self._tasks.cancel(edb_worker)
        for task in self._tasks.tasks():
            worker = task.worker
            if isinstance(worker, QThread) and worker.isRunning():
                worker.wait()
        for edb_worker in list(self._edb_workers):
            if edb_worker.isRunning():
                edb_worker.wait()
        super().closeEvent(event)

    def _on_scan_preset(self, command: str) -> None:
        # why: pre-fill the command builder with a nmap preset (target filled) for the user to
        # review and Run — never auto-executed (§7). Needs a profile for the target.
        if self._profile is None:
            return
        filled = expand(command, target=self._profile.target.ip)
        self._tool_panel.prefill_command(filled)
        self._tool_panel.append_output(f"[preset] loaded: {filled}")

    def _on_run(self) -> None:
        if self._profile is None or not self._tasks.can_start(exclusive=True):
            return
        self._tool_panel.append_output("[nmap] starting…")
        worker = NmapWorker(self._profile)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_scan_done)
        worker.failed.connect(self._on_run_failed)
        self._launch(worker, "nmap", exclusive=True)

    def _on_run_command(self, command: str) -> None:
        if self._profile is None or not self._tasks.can_start():
            return
        manual_dir = self._profile.directory / "manual"
        manual_dir.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha1(command.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]
        output_file = manual_dir / f"{_slug(command)}-{digest}.txt"
        with (manual_dir / "commands.txt").open("a", encoding="utf-8") as history:
            history.write(command + "\n")
        self._tool_panel.append_output(f"$ {command}")
        worker = CommandWorker(command, output_file, cwd=self._profile.directory)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(lambda code: self._command_done(code, None))
        worker.failed.connect(self._on_run_failed)
        self._launch(worker, _slug(command))

    def _on_http_run(self, command: str, output_rel: str, tool: str, port: int) -> None:
        if self._profile is None or not self._tasks.can_start() or not output_rel:
            return
        struct_path = _contained_path(self._profile.directory, output_rel)
        if struct_path is None:
            self._tool_panel.append_output(
                f"[blocked] output path must stay inside the profile: {output_rel}"
            )
            return
        struct_path.parent.mkdir(parents=True, exist_ok=True)
        self._tool_panel.append_output(f"$ {command}")
        worker = CommandWorker(
            command, struct_path.with_suffix(".log"), cwd=self._profile.directory
        )
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(
            lambda code: self._command_done(
                code, lambda: self._parse_http_output(struct_path, tool, port)
            )
        )
        worker.failed.connect(self._on_run_failed)
        self._launch(worker, f"http:{port}")

    def _on_http_dry_run(self, command: str) -> None:
        self._audit_action("dry-run", command=command)
        self._tool_panel.append_output(f"[dry-run] {command}")

    def _on_http_add_report(self, command: str) -> None:
        if self._profile is None:
            return
        manual_dir = self._profile.directory / "manual"
        manual_dir.mkdir(parents=True, exist_ok=True)
        with (manual_dir / "commands.txt").open("a", encoding="utf-8") as history:
            history.write(command + "\n")
        self._audit_action("add-to-report", command=command)
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
        if self._profile is None or not self._tasks.can_start() or not output_rel:
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
        self._tool_panel.append_output(f"$ {command}")
        worker = CommandWorker(
            command, struct_path.with_suffix(".log"), cwd=self._profile.directory
        )
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(
            lambda code: self._command_done(
                code, lambda: self._parse_vhost_output(struct_path, tool, domain)
            )
        )
        worker.failed.connect(self._on_run_failed)
        self._launch(worker, "vhost")

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
        if self._profile is None or not self._tasks.can_start():
            return
        out = _contained_path(self._profile.directory, output_rel)
        if out is None:
            return
        out.parent.mkdir(parents=True, exist_ok=True)
        self._tool_panel.append_output(f"$ {command}")
        worker = CommandWorker(command, out, cwd=self._profile.directory)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(
            lambda code: self._command_done(code, lambda: self._apply_wildcard_size(out))
        )
        worker.failed.connect(self._on_run_failed)
        self._launch(worker, "wildcard")

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
            or not self._tasks.can_start()
        ):
            return
        url = default_url(self._profile.target.ip, service.port, False)
        probe_out = self._profile.directory / "http" / str(service.port) / "probe.txt"
        probe_out.parent.mkdir(parents=True, exist_ok=True)
        self._tool_panel.append_output(f"[probe] curl -sIk {url}")
        worker = CommandWorker(f"curl -sIk {url}", probe_out, cwd=self._profile.directory)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(lambda code: self._probe_done(code, service))
        worker.failed.connect(self._on_run_failed)
        self._launch(worker, f"probe:{service.port}")

    def _probe_done(self, exit_code: int, service: DiscoveredService) -> None:
        if exit_code == 0 and self._profile is not None:
            for discovered in self._profile.discovered_services:
                if discovered.port == service.port and discovered.proto == service.proto:
                    discovered.service = "http"
            self._profile.save()
            self._tool_panel.append_output(f"[http] port {service.port} now treated as HTTP")
        else:
            self._tool_panel.append_output("[probe] no HTTP response")

    def _on_smb_recon(self, mode: str) -> None:
        if self._profile is None or not self._tasks.can_start():
            return
        self._tool_panel.append_output(f"[smb] {mode} recon starting…")
        worker = SmbReconWorker(self._profile, mode)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_smb_done)
        worker.failed.connect(self._on_run_failed)
        self._launch(worker, f"smb {mode}")

    def _on_smb_done(self, result: object) -> None:
        # why: a UI-thread write error must not escape — cleanup runs on the finished signal.
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

    def _on_ftp_recon(self, mode: str, port: int) -> None:
        if self._profile is None or not self._tasks.can_start():
            return
        self._tool_panel.append_output(f"[ftp] {mode} recon on port {port} starting…")
        worker = FtpReconWorker(self._profile, mode, port)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_ftp_done)
        worker.failed.connect(self._on_run_failed)
        self._launch(worker, f"ftp:{port}")

    def _on_ftp_done(self, result: object) -> None:
        # why: a UI-thread write error must not escape — cleanup runs on the finished signal.
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

    def _on_ssh_recon(self, port: int) -> None:
        if self._profile is None or not self._tasks.can_start():
            return
        self._tool_panel.append_output(f"[ssh] recon on port {port} starting…")
        worker = SshReconWorker(self._profile, port)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_ssh_done)
        worker.failed.connect(self._on_run_failed)
        self._launch(worker, f"ssh:{port}")

    def _on_ssh_done(self, result: object) -> None:
        # why: a UI-thread write error must not escape — cleanup runs on the finished signal.
        try:
            if isinstance(result, SshReconResult):
                self._tool_panel.set_ssh_summary(result.summary)
                self._tool_panel.append_output("[ssh] recon complete")
        except Exception as exc:  # boundary: never wedge the worker slot on a UI-thread write error
            self._tool_panel.append_output(f"[error] {exc}")

    def _on_simple_recon(self, module_name: str, port: int = 0) -> None:
        if self._profile is None or module_name not in SIMPLE_SPECS or not self._tasks.can_start():
            return
        self._tool_panel.append_output(f"[{module_name}] recon starting…")
        worker = SimpleReconWorker(self._profile, module_name, port)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_simple_done)
        worker.failed.connect(self._on_run_failed)
        self._launch(worker, module_name)

    def _on_simple_done(self, result: object) -> None:
        # why: a UI-thread write error must not escape — cleanup runs on the finished signal.
        try:
            if isinstance(result, SimpleReconResult):
                self._tool_panel.set_simple_summary(result.module, result.summary)
                self._tool_panel.append_output(f"[{result.module}] recon complete")
        except Exception as exc:  # boundary: never wedge the worker slot on a UI-thread write error
            self._tool_panel.append_output(f"[error] {exc}")

    def _on_dns_recon(self, domain: str, port: int) -> None:
        if self._profile is None or not self._tasks.can_start():
            return
        scope = f"zone {domain}" if domain else "no zone (version + recursion only)"
        self._tool_panel.append_output(f"[dns] recon on port {port} — {scope} starting…")
        worker = DnsReconWorker(self._profile, domain, port)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_dns_done)
        worker.failed.connect(self._on_run_failed)
        self._launch(worker, f"dns:{port}")

    def _on_dns_done(self, result: object) -> None:
        # why: a UI-thread write error must not escape — cleanup runs on the finished signal.
        try:
            if isinstance(result, DnsReconResult):
                self._tool_panel.set_dns_summary(result.summary)
                self._tool_panel.append_output("[dns] recon complete")
        except Exception as exc:  # boundary: never wedge the worker slot on a UI-thread write error
            self._tool_panel.append_output(f"[error] {exc}")

    def _on_ldap_recon(self, basedn: str, port: int) -> None:
        if self._profile is None or not self._tasks.can_start():
            return
        scope = f"base {basedn}" if basedn else "auto-discover base DN"
        self._tool_panel.append_output(f"[ldap] recon on port {port} — {scope} starting…")
        worker = LdapReconWorker(self._profile, basedn, port)
        worker.line.connect(self._tool_panel.append_output)
        worker.done.connect(self._on_ldap_done)
        worker.failed.connect(self._on_run_failed)
        self._launch(worker, f"ldap:{port}")

    def _on_ldap_done(self, result: object) -> None:
        # why: a UI-thread write error must not escape — cleanup runs on the finished signal.
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

    def _on_scan_done(self, count: int) -> None:
        self._tool_panel.append_output(f"[nmap] done — {count} services")

    def _command_done(self, exit_code: int, parse: Callable[[], None] | None) -> None:
        # why: the per-worker `parse` closure carries this command's own output context, so parallel
        # CommandWorkers can't clobber a shared parse slot. Worker cleanup runs on `finished`.
        self._tool_panel.append_output(f"[done] exit={exit_code}")
        if parse is not None:
            try:
                parse()
            except Exception as exc:  # boundary: a parse/write error must not wedge the task
                self._tool_panel.append_output(f"[parse] failed: {exc}")

    def _on_run_failed(self, message: str) -> None:
        self._tool_panel.append_output(f"[error] {message}")
