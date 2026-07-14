from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from datetime import UTC, datetime
from functools import partial
from importlib import metadata
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QThread
from PySide6.QtGui import QAction, QActionGroup, QCloseEvent, QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QDialog,
    QDockWidget,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
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

from oscprecon import config, edb, findings, references, spray, vault_export
from oscprecon.audit import Auditor
from oscprecon.branding import APP_NAME, APP_SUBTITLE, APP_TAGLINE
from oscprecon.gui import theme
from oscprecon.gui.assets import ICON, asset_path
from oscprecon.gui.dialogs import (
    AddCredentialDialog,
    CredentialVaultDialog,
    DoctorDialog,
    LogViewerDialog,
    NewProfileDialog,
    SettingsDialog,
    SprayDialog,
)
from oscprecon.gui.simple_recon import SIMPLE_SPECS
from oscprecon.gui.task_manager import TaskManager
from oscprecon.gui.theme import styles, tokens
from oscprecon.gui.widgets.activity_view import ActivityView
from oscprecon.gui.widgets.app_header import AppHeader
from oscprecon.gui.widgets.findings_view import FindingsView
from oscprecon.gui.widgets.graph_view import GraphView
from oscprecon.gui.widgets.nav_rail import NavRail
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
    LiveHacktricksWorker,
    NmapWorker,
    SearchsploitWorker,
    SimpleReconResult,
    SimpleReconWorker,
    SmbReconResult,
    SmbReconWorker,
    SshReconResult,
    SshReconWorker,
)
from oscprecon.gui.workspace import WorkspaceDashboard
from oscprecon.manual_commands import expand, load_manual_commands
from oscprecon.models import Credential, DiscoveredService, Target
from oscprecon.modules.http import default_url, detect_wordpress, parse_tool
from oscprecon.modules.vhost import parse_vhost_tool
from oscprecon.parsing import run_parser
from oscprecon.patterns.engine import suggest_for
from oscprecon.profile import Profile
from oscprecon.references.live_hacktricks import LiveResult
from oscprecon.workspace import locks, portability

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
        settings = config.load_settings()
        theme.apply_theme(settings.theme)
        theme.apply_font(settings.font_size)
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(QIcon(str(asset_path(ICON))))
        self.resize(1200, 720)
        self._profile: Profile | None = None
        self._auditor: Auditor | None = None
        self._locked_dir: Path | None = None  # the profile dir we currently hold an edit-lock on
        self._tasks = TaskManager(settings.max_concurrency)
        self._task_bar = TaskStatusBar(self._tasks)
        self._recent_menu: QMenu
        self._new_action: QAction
        self._open_action: QAction
        self._save_action: QAction

        self._target_label = QLabel("No profile loaded.")
        self._run_button = QPushButton("Run Full Recon")
        self._run_button.setStyleSheet(styles.primary_button(tokens.DARK))  # primary recon action
        self._run_button.setAccessibleName("Run full recon")
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
        self._reference_pane.refresh_requested.connect(self._on_live_refresh)
        self._reference_pane.set_live_enabled(settings.hacktricks_live_enabled)
        self._edb_request_id = 0
        self._edb_workers: set[QThread] = set()
        self._edb_context: tuple[str, str, str] | None = None  # (service label, product, version)
        self._live_request_id = 0
        self._live_workers: set[QThread] = set()
        self._spray_pending = 0  # launched sprays still running; clean input lists when it hits 0
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
        self._findings_view = FindingsView()
        self._activity_view = ActivityView()
        self._dashboard = WorkspaceDashboard()
        self._dashboard.open_requested.connect(lambda d: self._open_path(Path(str(d))))
        self._dashboard.create_requested.connect(self._on_new)
        self._dashboard.status_message.connect(self._tool_panel.append_output)
        self._dashboard.profile_mutated.connect(self._on_dashboard_mutated)
        self._central_stack = QStackedWidget()
        # index order is load-bearing (graph/report toggles + tests key on 0/1/2/3) — append only
        self._central_stack.addWidget(splitter)  # 0: three-pane recon
        self._central_stack.addWidget(self._graph_view)  # 1: graph
        self._central_stack.addWidget(self._report_view)  # 2: report preview
        self._central_stack.addWidget(self._dashboard)  # 3: workspace dashboard (home)
        self._central_stack.addWidget(self._findings_view)  # 4: findings
        self._central_stack.addWidget(self._activity_view)  # 5: activity / audit

        # app shell: compact header on top, primary nav rail on the left, central stack in the body
        theme_name = theme.normalize(settings.theme)
        self._header = AppHeader(theme_name)
        self._header.home_requested.connect(self._show_workspace)
        self._nav = NavRail(theme_name)
        self._nav.navigate.connect(self._on_navigate)
        self._tool_panel.set_theme(theme_name)
        self._restyle_views(theme_name)

        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)
        body_layout.addWidget(self._nav)
        body_layout.addWidget(self._central_stack, stretch=1)

        shell = QWidget()
        shell_layout = QVBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)
        shell_layout.addWidget(self._header)
        shell_layout.addWidget(body, stretch=1)
        self.setCentralWidget(shell)

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
        status.addWidget(QLabel(f"{APP_NAME} v{_app_version()}"))
        status.addWidget(self._status_profile)
        status.addWidget(self._status_workspace)
        status.addPermanentWidget(legal)
        self._update_status_footer()

        self._build_menus()
        # context-aware Find + Escape-to-dismiss (menu items already cover N/O/S/W/,/0/G/R)
        find_sc = QShortcut(QKeySequence.StandardKey.Find, self)  # Ctrl+F
        find_sc.activated.connect(self._on_find)
        esc_sc = QShortcut(QKeySequence(Qt.Key.Key_Escape), self)
        esc_sc.activated.connect(self._on_escape)
        self._load_last_profile()

    def _on_find(self) -> None:
        # focus the search of whatever view is showing; the reference-pane find only exists on the
        # recon three-pane (index 0), so Ctrl+F is a no-op on graph/report/activity
        current = self._central_stack.currentWidget()
        if current is self._dashboard:
            self._dashboard.focus_filter()
        elif current is self._findings_view:
            self._findings_view.focus_search()
        elif self._central_stack.currentIndex() == 0:
            self._reference_pane.focus_find()

    def _on_escape(self) -> None:
        self._tool_panel.clear_banner()

    def _update_status_footer(self) -> None:
        name = self._profile.profile_name if self._profile is not None else "no profile loaded"
        self._status_profile.setText(f"profile: {name}")
        self._status_workspace.setText(f"workspace: {config.workspace_root()}")

    def _build_menus(self) -> None:
        file_menu = self.menuBar().addMenu("&File")

        self._new_action = QAction("New Project...", self)
        self._new_action.setShortcut("Ctrl+N")
        self._new_action.triggered.connect(self._on_new)
        file_menu.addAction(self._new_action)

        self._open_action = QAction("Open Scan Profile...", self)
        self._open_action.setShortcut("Ctrl+O")
        self._open_action.triggered.connect(self._on_open)
        file_menu.addAction(self._open_action)

        self._open_by_ip_action = QAction("Open by IP...", self)
        self._open_by_ip_action.triggered.connect(self._on_open_by_ip)
        file_menu.addAction(self._open_by_ip_action)

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
        self._import_project_action = QAction("Import Project...", self)
        self._import_project_action.triggered.connect(self._on_import_project)
        file_menu.addAction(self._import_project_action)

        self._export_project_action = QAction("Export Project...", self)
        self._export_project_action.triggered.connect(self._on_export_project)
        file_menu.addAction(self._export_project_action)

        file_menu.addSeparator()
        prefs_action = QAction("Preferences...", self)
        prefs_action.setShortcut("Ctrl+,")
        prefs_action.triggered.connect(self._on_preferences)
        file_menu.addAction(prefs_action)

        file_menu.addSeparator()
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        scan_menu = self.menuBar().addMenu("&Scan")
        run_action = QAction("Run Full Recon", self)
        run_action.triggered.connect(self._on_run)
        scan_menu.addAction(run_action)

        profile_menu = scan_menu.addMenu("Run recon with profile")
        _PROFILE_HINTS = {
            "quick": "top-1000 TCP only — fastest triage",
            "default": "top-1000 → full -p- → UDP top-100 (standard)",
            "full": "standard battery + the slow full UDP sweep",
            "exam": "speed-tuned tight/fast, exam-legal (no vuln NSE)",
        }
        for profile_name in config.SCAN_PROFILES:
            action = QAction(profile_name.capitalize(), self)
            action.setToolTip(_PROFILE_HINTS.get(profile_name, ""))
            action.triggered.connect(
                lambda _checked=False, name=profile_name: self._start_recon(name)
            )
            profile_menu.addAction(action)

        presets_menu = scan_menu.addMenu("Nmap presets")
        for preset in load_manual_commands(_SCAN_PRESETS):
            action = QAction(preset.description, self)
            action.setToolTip(preset.why)
            action.triggered.connect(
                lambda _checked=False, cmd=preset.command: self._on_scan_preset(cmd)
            )
            presets_menu.addAction(action)

        scan_menu.addSeparator()
        spray_action = QAction("Credential Spray...", self)
        spray_action.triggered.connect(self._on_credential_spray)
        scan_menu.addAction(spray_action)

        edit_menu = self.menuBar().addMenu("&Edit")
        add_cred_action = QAction("Add Credential...", self)
        add_cred_action.triggered.connect(self._on_add_credential)
        edit_menu.addAction(add_cred_action)
        vault_action = QAction("Credential Vault...", self)
        vault_action.triggered.connect(self._on_credential_vault)
        edit_menu.addAction(vault_action)

        view_menu = self.menuBar().addMenu("&View")
        workspace_action = QAction("Workspace Dashboard", self)
        workspace_action.setShortcut("Ctrl+0")
        workspace_action.triggered.connect(self._show_workspace)
        view_menu.addAction(workspace_action)
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
        current_theme = theme.normalize(config.load_settings().theme)
        for name in theme.THEMES:
            action = QAction(theme.label(name), self, checkable=True)
            action.setChecked(name == current_theme)
            action.triggered.connect(lambda _checked=False, n=name: self._set_theme(n))
            self._theme_group.addAction(action)
            theme_menu.addAction(action)

        wordlists_action = QAction("Browse Wordlists...", self)
        wordlists_action.triggered.connect(self._on_browse_wordlists)
        view_menu.addAction(wordlists_action)

        help_menu = self.menuBar().addMenu("&Help")
        doctor_action = QAction("Doctor (tool status)...", self)
        doctor_action.triggered.connect(self._on_doctor)
        help_menu.addAction(doctor_action)
        log_action = QAction("View Diagnostics Log...", self)
        log_action.triggered.connect(self._on_view_log)
        help_menu.addAction(log_action)
        help_menu.addSeparator()
        about_action = QAction(f"About {APP_NAME}...", self)
        about_action.triggered.connect(self._on_about)
        help_menu.addAction(about_action)

    def _on_doctor(self) -> None:
        DoctorDialog(self).exec()

    def _on_view_log(self) -> None:
        LogViewerDialog(self).exec()

    def _on_about(self) -> None:
        QMessageBox.about(
            self,
            f"About {APP_NAME}",
            f"<h3>{APP_NAME}</h3>"
            f"<p>{APP_TAGLINE} — v{_app_version()}</p>"
            f"<p style='color:#8a94a6'>{APP_SUBTITLE}.<br>"
            "Wraps standard OSCP-allowed enumeration tools; runs offline, "
            "makes no exploit or LLM calls at runtime.</p>",
        )

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
        if self._profile is not None and self._profile.read_only:
            return  # read-only mode makes no writes — including the audit log
        if self._auditor is not None:
            self._auditor.record(action, details=details)

    def _release_lock(self) -> None:
        if self._locked_dir is not None:
            locks.release(self._locked_dir)
            self._locked_dir = None

    def _resolve_lock(self, profile: Profile) -> bool:
        # returns True to proceed (may set profile.read_only), False if the user cancels. A stale /
        # malformed / absent lock proceeds (recovered by _set_profile); a LIVE lock held by another
        # instance prompts for read-only vs cancel.
        directory = profile.directory
        if directory == self._locked_dir:
            return True  # already ours
        info, _malformed = locks.read_lock(directory)
        if info is None or locks.is_stale(info):
            return True
        detail = (
            f"PID {info.pid} on {info.hostname} (v{info.app_version}, since {info.started_at[:19]})"
        )
        box = QMessageBox(self)
        box.setTextFormat(Qt.TextFormat.PlainText)  # profile name/host are attacker-influenced
        box.setWindowTitle("Profile in use")
        box.setText(f"“{profile.profile_name}” is open in another window.\n\n{detail}")
        ro_btn = box.addButton("Open read-only", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() is ro_btn:
            profile.read_only = True
            return True
        return False

    def _set_profile(self, profile: Profile) -> None:
        self._release_lock()  # drop the previously-open profile's edit lock
        if not profile.read_only:
            acquired = locks.acquire(profile.directory)
            if acquired is None:
                acquired = locks.recover_stale(profile.directory)  # clears a stale/malformed lock
            if acquired is not None:
                self._locked_dir = profile.directory
            else:  # a live / foreign lock we can't take -> fall back to read-only
                profile.read_only = True
        self._profile = profile
        self._auditor = Auditor(profile.directory, profile.profile_name)
        if not profile.read_only:
            profile.mark_opened()
            profile.save()  # persist last_opened_at
        target = profile.target
        label = f"{profile.profile_name} — {target.ip}"
        if target.hostname:
            label += f" ({target.hostname})"
        if profile.read_only:
            label += "   [READ-ONLY]"
        self._target_label.setText(label)
        ro = " [read-only]" if profile.read_only else ""
        self.setWindowTitle(f"{APP_NAME} — {profile.profile_name}{ro}")
        self._header.set_profile(
            profile.profile_name, target.ip, target.hostname or "", read_only=profile.read_only
        )
        self._nav.set_enabled_keys(True)
        self._central_stack.setCurrentIndex(0)  # leave the dashboard, show the three-pane view
        self._sync_nav()
        self._tool_panel.set_target(target.ip)
        self._tool_panel.set_profile(profile)
        self._service_tree.populate(profile.discovered_services, force=True)
        self._graph_view.set_profile(profile)
        self._report_view.set_profile(profile)
        self._findings_view.set_profile(profile)
        self._activity_view.set_profile(profile)
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

    def _on_dashboard_mutated(self, directory: object) -> None:
        # a dashboard org edit wrote profile.json for `directory`. If that is the profile we hold in
        # memory, re-read its organization so a later self._profile.save() can't clobber it with
        # a stale copy. (Same-thread/direct signal, so this runs before any later save.)
        if self._profile is not None and Path(str(directory)) == self._profile.directory:
            try:
                fresh = Profile.load(self._profile.directory)
            except (OSError, ValueError, KeyError):
                return
            self._profile.organization = fresh.organization
            self._profile.tags = fresh.tags

    # central-stack index -> nav key, so the rail highlight always matches the visible view
    _INDEX_KEY = {0: "recon", 1: "graph", 2: "report", 3: "workspace", 4: "findings", 5: "activity"}

    def _sync_nav(self) -> None:
        self._nav.set_current(self._INDEX_KEY.get(self._central_stack.currentIndex(), "workspace"))

    def _on_navigate(self, key: str) -> None:
        # page destinations switch the central view; action destinations trigger a surface and let
        # the highlight bounce back to the current page
        if key == "workspace":
            self._show_workspace()
        elif key == "recon":
            self._show_recon()
        elif key == "graph":
            self._graph_action.setChecked(True)
        elif key == "report":
            self._report_action.setChecked(True)
        elif key == "findings":
            self._show_findings()
        elif key == "activity":
            self._show_activity()
        elif key == "credentials":
            self._on_credential_vault()
            self._sync_nav()
        elif key == "notes":
            self._notes_dock.setVisible(True)
            self._notes_dock.raise_()
            self._sync_nav()

    def _show_workspace(self) -> None:
        self._graph_action.setChecked(False)
        self._report_action.setChecked(False)
        self._nav.set_enabled_keys(
            self._profile is not None
        )  # only Workspace works with no project
        self._dashboard.refresh()  # rescan off-thread
        self._central_stack.setCurrentWidget(self._dashboard)
        self._sync_nav()

    def _show_recon(self) -> None:
        self._graph_action.setChecked(False)
        self._report_action.setChecked(False)
        self._central_stack.setCurrentIndex(0)
        self._sync_nav()

    def _show_findings(self) -> None:
        self._graph_action.setChecked(False)
        self._report_action.setChecked(False)
        self._findings_view.reload()
        self._central_stack.setCurrentWidget(self._findings_view)
        self._sync_nav()

    def _show_activity(self) -> None:
        self._graph_action.setChecked(False)
        self._report_action.setChecked(False)
        self._activity_view.reload()
        self._central_stack.setCurrentWidget(self._activity_view)
        self._sync_nav()

    def _on_toggle_graph(self, checked: bool) -> None:
        if checked:
            self._report_action.setChecked(False)  # graph and report are mutually exclusive views
            self._graph_view.reload()  # refresh from the latest findings/creds/graph.json
        self._central_stack.setCurrentIndex(1 if checked else 0)
        self._sync_nav()

    def _on_toggle_report(self, checked: bool) -> None:
        if checked:
            self._graph_action.setChecked(False)
            self._report_view.reload()  # render the current report.md
        self._central_stack.setCurrentIndex(2 if checked else 0)
        self._sync_nav()

    def _set_theme(self, name: str) -> None:
        theme.apply_theme(name)
        settings = config.load_settings()
        settings.theme = theme.normalize(name)
        config.save_settings(settings)
        self._restyle_shell(settings.theme)

    def _restyle_shell(self, theme_name: str) -> None:
        normalized = theme.normalize(theme_name)
        self._header.restyle(normalized)
        self._nav.restyle(normalized)
        self._tool_panel.set_theme(normalized)
        self._restyle_views(normalized)

    def _restyle_views(self, theme_name: str) -> None:
        self._reference_pane.set_theme(theme_name)
        self._findings_view.set_theme(theme_name)
        self._activity_view.set_theme(theme_name)
        self._dashboard.set_theme(theme_name)

    def _on_preferences(self) -> None:
        dialog = SettingsDialog(config.load_settings(), self)
        dialog.applied.connect(self._apply_settings)
        dialog.exec()

    def _apply_settings(self, settings: object) -> None:
        if not isinstance(settings, config.Settings):
            return
        theme.apply_theme(settings.theme)
        theme.apply_font(settings.font_size)
        self._sync_theme_menu(settings.theme)
        self._restyle_shell(settings.theme)
        self._tasks.max_concurrency = settings.max_concurrency
        self._reference_pane.set_live_enabled(settings.hacktricks_live_enabled)
        self._update_status_footer()
        self._dashboard.refresh()  # workspace root may have changed
        self._audit_action("settings-changed", theme=settings.theme)

    def _sync_theme_menu(self, name: str) -> None:
        for action in self._theme_group.actions():
            action.setChecked(action.text().lower() == name)

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
        self._show_workspace()  # nothing to restore -> land on the workspace dashboard

    def _on_service_selected(self, service: object) -> None:
        selected = service if isinstance(service, DiscoveredService) else None
        ref = references.match(selected) if selected is not None else None
        self._tool_panel.show_service(selected, ref)
        # findings for this service feed the reference pane's finding-aware HackTricks jump
        service_findings = None
        if selected is not None and ref is not None and self._profile is not None:
            service_findings = [
                f
                for f in findings.load_findings(self._profile.directory)
                if f.get("module") == ref.module
            ]
        self._reference_pane.show_service(selected, ref, service_findings)
        self._live_request_id += 1  # supersede any in-flight live fetch for a prior service
        if ref is not None:
            self._maybe_fetch_live(ref)
        self._edb_request_id += 1
        if selected is None or not selected.product or self._profile is None:
            return
        output_file = (
            self._profile.directory
            / "references"
            / f"edb-{selected.port}-{selected.proto.value}.json"
        )
        self._edb_context = (
            f"{selected.port}/{selected.proto.value} {selected.service}".strip(),
            selected.product,
            selected.version,
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
            self._persist_edb(hits)

    # ----- live HackTricks (§14a) ------------------------------------------

    def _maybe_fetch_live(self, ref: object) -> None:
        # auto behaviour on service selection (manual Refresh is _on_live_refresh):
        #   live enabled + auto-refresh -> fetch (serves fresh cache, refetches when stale)
        #   live enabled + prefer-live  -> serve an existing cache only, no network
        settings = config.load_settings()
        if not settings.hacktricks_live_enabled:
            return
        url = getattr(ref, "hacktricks", "")
        if not url:
            return
        if settings.hacktricks_auto_refresh:
            self._dispatch_live(url, enabled=True, force=False)
        elif settings.hacktricks_prefer_live:
            self._dispatch_live(url, enabled=False, force=False)  # cache-only, never fetches

    def _on_live_refresh(self) -> None:
        url = self._reference_pane.current_ref_url()
        if url and config.load_settings().hacktricks_live_enabled:
            self._live_request_id += 1
            self._audit_action("hacktricks-live-refresh", url=url)  # a reference action (§6a)
            self._dispatch_live(url, enabled=True, force=True)  # explicit user action

    def _dispatch_live(self, url: str, *, enabled: bool, force: bool) -> None:
        settings = config.load_settings()
        worker = LiveHacktricksWorker(
            url,
            enabled=enabled,
            force=force,
            max_age_days=settings.hacktricks_cache_days,
            request_id=self._live_request_id,
        )
        worker.done.connect(self._on_live_done)
        worker.finished.connect(lambda w=worker: self._live_workers.discard(w))
        self._live_workers.add(worker)
        worker.start()

    def _on_live_done(self, result: object, request_id: int) -> None:
        if request_id != self._live_request_id:
            return  # a newer service/project selection superseded this fetch
        if isinstance(result, LiveResult):
            self._reference_pane.apply_live_result(result)

    def _persist_edb(self, hits: list[Any]) -> None:
        # record the EDB references (lookup-only) into report.md; skipped in read-only mode.
        if (
            self._profile is None
            or self._profile.read_only
            or not hits
            or self._edb_context is None
        ):
            return
        service, product, version = self._edb_context
        edb.add_edb(
            self._profile.directory, service=service, product=product, version=version, hits=hits
        )

    def _on_page_visited(self, label: str, url: str) -> None:
        if self._profile is None or self._profile.read_only:
            return  # read-only: don't record reference visits
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
        if not self._resolve_lock(profile):
            return  # user cancelled a locked-profile prompt
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

    def _on_open_by_ip(self) -> None:
        ip, ok = QInputDialog.getText(self, "Open by IP", "Target IP or hostname:")
        if not ok or not ip.strip():
            return
        matches = portability.find_profiles_by_ip(config.workspace_root(), ip.strip())
        if not matches:
            QMessageBox.information(self, "No match", f"No profile targets {ip.strip()}.")
            return
        if len(matches) == 1:
            self._open_path(matches[0])
            return
        names = [p.name for p in matches]
        choice, chose = QInputDialog.getItem(
            self,
            "Multiple matches",
            f"{len(matches)} profiles target {ip.strip()}:",
            names,
            0,
            False,
        )
        if chose and choice:
            self._open_path(matches[names.index(choice)])

    def _on_import_project(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(
            self,
            "Import Project",
            str(config.workspace_root()),
            "Project archives (*.tar.gz *.tgz *.tar);;All files (*)",
        )
        if not chosen:
            return
        root = config.workspace_root()
        try:
            dest = portability.import_project_archive(Path(chosen), root)
        except portability.ProjectExistsError:
            answer = QMessageBox.question(
                self,
                "Profile exists",
                "A profile with that name already exists.\nReplace it with the imported copy?",
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
            try:
                dest = portability.import_project_archive(Path(chosen), root, overwrite=True)
            except portability.ProjectArchiveError as exc:
                QMessageBox.warning(self, "Import failed", str(exc))
                return
        except portability.ProjectArchiveError as exc:
            QMessageBox.warning(self, "Import failed", str(exc))
            return
        self._audit_action("project-imported", source=str(chosen))
        self._open_path(dest)

    def _on_export_project(self) -> None:
        if self._profile is None:
            QMessageBox.warning(self, "No profile", "Open or create a profile first.")
            return
        confirm = QMessageBox.warning(
            self,
            "Export Project",
            "The archive includes creds.json (plaintext credentials).\n"
            "Store and transfer it as sensitive. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        default = str(config.workspace_root() / f"{self._profile.profile_name}.tar.gz")
        chosen, _ = QFileDialog.getSaveFileName(
            self, "Export Project", default, "Project archive (*.tar.gz)"
        )
        if not chosen:
            return
        if not self._profile.read_only:  # keep the on-disk copy current before packing
            self._notes_pane.flush()
            self._profile.save()
        try:
            out = portability.export_project_archive(self._profile.directory, Path(chosen))
        except portability.ProjectArchiveError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        self._audit_action("project-exported", dest=str(out))
        self._tool_panel.append_output(f"[exported] {out}")
        QMessageBox.information(
            self,
            "Project exported",
            f"Archive written to:\n{out}\n\nIncludes creds.json — treat it as sensitive.",
        )

    def _on_add_credential(self) -> None:
        if self._profile is None:
            QMessageBox.information(self, "No profile", "Open or create a profile first.")
            return
        if self._profile.read_only:
            QMessageBox.information(self, "Read-only", "This profile is open read-only.")
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

    def _on_credential_vault(self) -> None:
        if self._profile is None:
            QMessageBox.information(self, "No profile", "Open or create a profile first.")
            return
        dialog = CredentialVaultDialog(self._profile, self)
        dialog.secret_copied.connect(
            lambda username: self._audit_action("credential-secret-copied", username=username)
        )
        dialog.exec()
        self._audit_action("credential-vault-opened")
        self._refresh_suggestions()  # has_credential may have changed

    def _on_credential_spray(self) -> None:
        if self._profile is None:
            QMessageBox.information(self, "No profile", "Open or create a profile first.")
            return
        if self._profile.read_only:
            QMessageBox.information(self, "Read-only", "This profile is open read-only.")
            return
        dialog = SprayDialog(self._profile, config.load_settings().spray_enabled, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        # re-read the setting at launch — the single gate; never pass spray=True otherwise.
        if not config.load_settings().spray_enabled:
            return
        users, passwords = spray.vault_material(self._profile.credentials())
        if not users or not passwords:
            QMessageBox.warning(
                self, "Empty vault", "Add usernames and passwords in the Credential Vault first."
            )
            return
        users_path, passwords_path = spray.write_spray_lists(
            self._profile.directory, users, passwords
        )
        profile = self._profile  # capture: results/cleanup always target the ORIGINATING profile
        target = profile.target.ip
        redact = spray.make_redactor(passwords)  # mask winning secrets in streamed tool output
        launched = 0
        for service in dialog.selected_services():
            if not self._tasks.can_start():
                break
            port = spray.discovered_port(service, profile.discovered_services)
            command = spray.build_spray_command(service, target, users_path, passwords_path, port)
            output_file = profile.directory / "spray" / f"{service}.txt"
            spray.secure_output_file(output_file)  # 0600 — it can hold plaintext secrets
            self._tool_panel.append_output(f"$ [spray] {command}")
            self._audit_action("credential-spray", service=service, target=target)
            worker = CommandWorker(command, output_file, cwd=profile.directory, spray=True)
            self._start(
                worker,
                f"spray:{service}",
                partial(
                    self._spray_done, profile=profile, service=service, output_file=output_file
                ),
                line_filter=redact,
            )
            launched += 1
        self._spray_pending = launched  # set before any queued done-callback runs (GUI thread)

    def _spray_done(self, code: int, profile: Profile, service: str, output_file: Path) -> None:
        self._record_spray_success(profile, service, output_file)
        self._command_done(code, None)
        self._spray_pending -= 1
        if self._spray_pending <= 0:  # last spray of this launch finished -> drop the input lists
            removed = spray.clean_spray_artifacts(profile.directory)
            if removed and profile is self._profile:
                self._tool_panel.append_output(f"[spray] removed input lists: {', '.join(removed)}")

    def _record_spray_success(self, profile: Profile, service: str, output_file: Path) -> None:
        # ADD-only confirmation into the originating project's creds.json — never removes a
        # credential, never touches a different active project, never logs the secret.
        try:
            output = Path(output_file).read_text(encoding="utf-8")
        except OSError:
            return
        cred_list = profile.credentials()
        candidates = [(c.username, c.secret) for c in cred_list if c.secret_type == "password"]
        confirmed = set(spray.parse_spray_success(service, output, candidates))
        if not confirmed or profile.read_only:
            return
        label = f"spray-confirmed:{service}"
        changed = False
        for cred in cred_list:
            if (cred.username, cred.secret) in confirmed and label not in cred.tested_against:
                cred.tested_against.append(label)
                changed = True
        if changed:
            profile.set_credentials(cred_list)
            if profile is self._profile:
                self._tool_panel.append_output(f"[spray] confirmed {len(confirmed)} credential(s)")
                # audit the OUTCOME (a credential validated) — service + count only, no secret
                self._audit_action("spray-confirmed", service=service, count=len(confirmed))

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
        read_only = self._profile is not None and self._profile.read_only
        self._new_action.setEnabled(not any_running)
        self._open_action.setEnabled(not any_running)
        self._open_by_ip_action.setEnabled(not any_running)
        self._import_project_action.setEnabled(not any_running)
        # export packs the profile dir — gate it so a snapshot isn't taken mid-scan-write
        self._export_project_action.setEnabled(not any_running and self._profile is not None)
        self._save_action.setEnabled(not any_running and not read_only)
        self._recent_menu.setEnabled(not any_running)
        self._run_button.setEnabled(
            self._profile is not None and self._tasks.can_start(exclusive=True) and not read_only
        )
        # why: keep the tree browseable (selecting a service is read-only) — only the launch
        # buttons in the tool panel are gated on capacity, via set_running. A read-only profile
        # disables every recon launch (a worker would write findings/creds -> ReadOnlyError).
        self._service_tree.setEnabled(self._profile is not None)
        self._tool_panel.set_running(read_only or not self._tasks.can_start())
        self._notes_pane.setEnabled(not read_only)  # no notes edits in read-only
        self._header.set_task_count(self._tasks.active_count)

    def _launch(self, worker: QThread, label: str, *, exclusive: bool = False) -> None:
        # admission primitive: register with the TaskManager, guarantee release on `finished`
        # (fires once, after run() returns — so a raising done/failed slot can't wedge the slot),
        # audit the start, refresh the busy-gates, and start the thread.
        self._tasks.add(worker, label, exclusive=exclusive)
        worker.finished.connect(lambda: self._release(worker))
        self._audit_action("run", label=label, exclusive=exclusive)
        self._refresh_busy()
        worker.start()

    def _start(
        self,
        worker: CancellableThread,
        label: str,
        on_done: Callable[[Any], None],  # done payload is int (nmap/command) or a Result object
        *,
        exclusive: bool = False,
        line_filter: Callable[[str], str] | None = None,
    ) -> None:
        # one lifecycle path for a line/done/failed worker: wire the streaming output, the result
        # slot, and the failure slot, then admit via _launch. Callers bind the originating profile
        # into `on_done` so a stale completion persists to the profile that started it, not the
        # profile that happens to be active when it finishes. `signals`: every worker declares
        # line/done/failed on its own subclass, not on the CancellableThread base mypy sees here.
        # `line_filter` redacts secrets from streamed output (spray) before it reaches the UI/logs.
        signals: Any = worker
        if line_filter is None:
            signals.line.connect(self._tool_panel.append_output)
        else:
            redact = line_filter
            signals.line.connect(lambda line: self._tool_panel.append_output(redact(line)))
        signals.done.connect(on_done)
        signals.failed.connect(self._on_run_failed)
        self._launch(worker, label, exclusive=exclusive)

    def _release(self, worker: QThread) -> None:
        if not any(task.worker is worker for task in self._tasks.tasks()):
            return  # already released — never double-remove / double-audit / double-refresh
        worker.wait()  # finished has fired — returns immediately
        label = next((task.label for task in self._tasks.tasks() if task.worker is worker), "")
        self._tasks.remove(worker)
        worker.deleteLater()
        self._audit_action("run-finished", label=label)
        self._post_run_refresh()

    def _record_creds(self, profile: Profile, creds: list[Credential]) -> None:
        # creds always persist to the ORIGINATING profile; the echo line only shows when that
        # profile is still active (else it would print into another profile's output pane).
        for cred in creds:
            profile.add_credential(cred)
            if profile is self._profile:
                self._tool_panel.append_output(f"[cred] {cred.username} (source: {cred.source})")

    def _post_run_refresh(self) -> None:
        # why: this fires on EVERY worker completion (up to 4 in parallel). Refresh only what a
        # background run can change — services tree, graph, suggestions, status — and never reload
        # the notes editor / command builder / window title / recent menu (that churns the user's
        # context mid-work). The tree/notes widgets are idempotent, so an unchanged set is a no-op.
        if self._profile is not None:
            if self._pending_visits and not self._profile.read_only:
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
        if self._profile is None or not self._profile.read_only:
            self._notes_pane.flush()  # no notes write in read-only mode
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
        for live_worker in list(self._live_workers):  # let live HackTricks fetches finish cleanly
            if live_worker.isRunning():
                live_worker.wait()
        self._dashboard.shutdown()  # stop any in-flight workspace scan
        self._release_lock()  # best-effort lock release on shutdown
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
        # Run Full Recon button/menu → uses the configured default scan profile.
        self._start_recon(None)

    def _start_recon(self, scan_profile: str | None) -> None:
        # scan_profile=None → the configured default; a submenu passes an explicit override for
        # this one run without changing the saved preference.
        if self._profile is None or not self._tasks.can_start(exclusive=True):
            return
        settings = config.load_settings()
        profile_name = scan_profile or settings.scan_profile
        self._tool_panel.append_output(f"[nmap] starting… (scan profile: {profile_name})")
        worker = NmapWorker(
            self._profile, udp_full=settings.nmap_udp_full, scan_profile=profile_name
        )
        self._start(worker, "nmap", self._on_scan_done, exclusive=True)

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
        self._start(worker, _slug(command), lambda code: self._command_done(code, None))

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
        prof = self._profile
        worker = CommandWorker(command, struct_path.with_suffix(".log"), cwd=prof.directory)
        self._start(
            worker,
            f"http:{port}",
            lambda code: self._command_done(
                code, lambda: self._parse_http_output(prof, struct_path, tool, port)
            ),
        )

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

    def _parse_http_output(self, profile: Profile, struct_path: Path, tool: str, port: int) -> None:
        # `profile` is the originating profile captured at launch — findings persist there even if
        # the user switched profiles; UI echoes only when it is still the active profile.
        try:
            text = struct_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        hits = run_parser(
            lambda: parse_tool(tool, text, port),
            label=f"http {tool}",
            on_line=self._tool_panel.append_output,
        )
        if hits:
            now = datetime.now(UTC).isoformat()
            findings.add_findings(profile.directory, [h.to_dict(now) for h in hits])
            if profile is self._profile:
                self._tool_panel.append_output(
                    f"[findings] +{len(hits)} from {tool} -> findings.json"
                )
        if detect_wordpress(text) and profile is self._profile:
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
        prof = self._profile
        worker = CommandWorker(command, struct_path.with_suffix(".log"), cwd=prof.directory)
        self._start(
            worker,
            "vhost",
            lambda code: self._command_done(
                code, lambda: self._parse_vhost_output(prof, struct_path, tool, domain)
            ),
        )

    def _parse_vhost_output(
        self, profile: Profile, struct_path: Path, tool: str, domain: str
    ) -> None:
        # ffuf/gobuster write -o (struct_path); dnsrecon/wfuzz write stdout (captured to the .log)
        path = struct_path if struct_path.exists() else struct_path.with_suffix(".log")
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        hits = run_parser(
            lambda: parse_vhost_tool(tool, text, domain),
            label=f"vhost {tool}",
            on_line=self._tool_panel.append_output,
        )
        if hits:
            now = datetime.now(UTC).isoformat()
            findings.add_findings(profile.directory, [h.to_dict(now) for h in hits])
            if profile is self._profile:
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
        self._start(
            worker,
            "wildcard",
            lambda code: self._command_done(code, lambda: self._apply_wildcard_size(out)),
        )

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
        prof = self._profile
        worker = CommandWorker(f"curl -sIk {url}", probe_out, cwd=prof.directory)
        self._start(
            worker, f"probe:{service.port}", lambda code: self._probe_done(code, prof, service)
        )

    def _probe_done(self, exit_code: int, profile: Profile, service: DiscoveredService) -> None:
        if exit_code != 0:
            if profile is self._profile:
                self._tool_panel.append_output("[probe] no HTTP response")
            return
        for discovered in profile.discovered_services:  # mutate the originating profile
            if discovered.port == service.port and discovered.proto == service.proto:
                discovered.service = "http"
        profile.save()
        if profile is self._profile:
            self._tool_panel.append_output(f"[http] port {service.port} now treated as HTTP")

    def _on_smb_recon(self, mode: str) -> None:
        if self._profile is None or not self._tasks.can_start():
            return
        self._tool_panel.append_output(f"[smb] {mode} recon starting…")
        prof = self._profile
        worker = SmbReconWorker(prof, mode)
        self._start(worker, f"smb {mode}", lambda r: self._on_smb_done(r, prof))

    def _on_smb_done(self, result: object, profile: Profile) -> None:
        # why: a UI-thread write error must not escape — cleanup runs on the finished signal.
        try:
            if isinstance(result, SmbReconResult):
                self._record_creds(profile, result.creds)
                if profile is self._profile:  # only touch the panel if this profile is still active
                    self._tool_panel.set_smb_summary(result.summary)
                    self._tool_panel.append_output("[smb] recon complete")
        except Exception as exc:  # boundary: never wedge the worker slot on a UI-thread write error
            self._tool_panel.append_output(f"[error] {exc}")

    def _on_ftp_recon(self, mode: str, port: int) -> None:
        if self._profile is None or not self._tasks.can_start():
            return
        self._tool_panel.append_output(f"[ftp] {mode} recon on port {port} starting…")
        prof = self._profile
        worker = FtpReconWorker(prof, mode, port)
        self._start(worker, f"ftp:{port}", lambda r: self._on_ftp_done(r, prof))

    def _on_ftp_done(self, result: object, profile: Profile) -> None:
        # why: a UI-thread write error must not escape — cleanup runs on the finished signal.
        try:
            if isinstance(result, FtpReconResult):
                self._record_creds(profile, result.creds)
                if profile is self._profile:
                    self._tool_panel.set_ftp_summary(result.summary)
                    self._tool_panel.append_output("[ftp] recon complete")
        except Exception as exc:  # boundary: never wedge the worker slot on a UI-thread write error
            self._tool_panel.append_output(f"[error] {exc}")

    def _on_ssh_recon(self, port: int) -> None:
        if self._profile is None or not self._tasks.can_start():
            return
        self._tool_panel.append_output(f"[ssh] recon on port {port} starting…")
        prof = self._profile
        worker = SshReconWorker(prof, port)
        self._start(worker, f"ssh:{port}", lambda r: self._on_ssh_done(r, prof))

    def _on_ssh_done(self, result: object, profile: Profile) -> None:
        # why: a UI-thread write error must not escape — cleanup runs on the finished signal.
        try:
            if isinstance(result, SshReconResult) and profile is self._profile:
                self._tool_panel.set_ssh_summary(result.summary)
                self._tool_panel.append_output("[ssh] recon complete")
        except Exception as exc:  # boundary: never wedge the worker slot on a UI-thread write error
            self._tool_panel.append_output(f"[error] {exc}")

    def _on_simple_recon(self, module_name: str, port: int = 0) -> None:
        if self._profile is None or module_name not in SIMPLE_SPECS or not self._tasks.can_start():
            return
        self._tool_panel.append_output(f"[{module_name}] recon starting…")
        prof = self._profile
        worker = SimpleReconWorker(prof, module_name, port)
        self._start(worker, module_name, lambda r: self._on_simple_done(r, prof))

    def _on_simple_done(self, result: object, profile: Profile) -> None:
        # why: a UI-thread write error must not escape — cleanup runs on the finished signal.
        try:
            if isinstance(result, SimpleReconResult) and profile is self._profile:
                self._tool_panel.set_simple_summary(result.module, result.summary)
                self._tool_panel.append_output(f"[{result.module}] recon complete")
        except Exception as exc:  # boundary: never wedge the worker slot on a UI-thread write error
            self._tool_panel.append_output(f"[error] {exc}")

    def _on_dns_recon(self, domain: str, port: int) -> None:
        if self._profile is None or not self._tasks.can_start():
            return
        scope = f"zone {domain}" if domain else "no zone (version + recursion only)"
        self._tool_panel.append_output(f"[dns] recon on port {port} — {scope} starting…")
        prof = self._profile
        worker = DnsReconWorker(prof, domain, port)
        self._start(worker, f"dns:{port}", lambda r: self._on_dns_done(r, prof))

    def _on_dns_done(self, result: object, profile: Profile) -> None:
        # why: a UI-thread write error must not escape — cleanup runs on the finished signal.
        try:
            if isinstance(result, DnsReconResult) and profile is self._profile:
                self._tool_panel.set_dns_summary(result.summary)
                self._tool_panel.append_output("[dns] recon complete")
        except Exception as exc:  # boundary: never wedge the worker slot on a UI-thread write error
            self._tool_panel.append_output(f"[error] {exc}")

    def _on_ldap_recon(self, basedn: str, port: int) -> None:
        if self._profile is None or not self._tasks.can_start():
            return
        scope = f"base {basedn}" if basedn else "auto-discover base DN"
        self._tool_panel.append_output(f"[ldap] recon on port {port} — {scope} starting…")
        prof = self._profile
        worker = LdapReconWorker(prof, basedn, port)
        self._start(worker, f"ldap:{port}", lambda r: self._on_ldap_done(r, prof))

    def _on_ldap_done(self, result: object, profile: Profile) -> None:
        # why: a UI-thread write error must not escape — cleanup runs on the finished signal.
        try:
            if isinstance(result, LdapReconResult):
                self._record_creds(profile, result.creds)
                if profile is self._profile:
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
