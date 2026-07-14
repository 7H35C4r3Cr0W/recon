from __future__ import annotations

import re

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from oscprecon.gui.simple_recon import SIMPLE_SPECS
from oscprecon.gui.widgets.banner import Banner
from oscprecon.gui.widgets.dns_panel import DnsPanel
from oscprecon.gui.widgets.ftp_panel import FtpPanel
from oscprecon.gui.widgets.http_panel import HttpPanel
from oscprecon.gui.widgets.ldap_panel import LdapPanel
from oscprecon.gui.widgets.simple_recon_panel import SimpleReconPanel
from oscprecon.gui.widgets.smb_panel import SmbPanel
from oscprecon.gui.widgets.ssh_panel import SshPanel
from oscprecon.gui.widgets.vhost_panel import VhostPanel
from oscprecon.models import DiscoveredService, Suggestion
from oscprecon.profile import Profile
from oscprecon.references import ServiceRef, expand_hint

_COMMAND_ROLE = Qt.ItemDataRole.UserRole

# leading [tag] on a status line -> banner kind. Untagged lines (raw tool output) never touch the
# banner. Only actionable/outcome tags surface; info chatter (running/dry-run) stays in the log.
_TAG_RE = re.compile(r"^\[([a-z][a-z-]*)\]")
_TAG_KIND = {
    "blocked": "error",
    "error": "error",
    "missing": "warning",
    "warning": "warning",
    "drift": "warning",
    "done": "success",
    "restored": "success",
    "exported": "success",
    "imported": "success",
}


class ToolPanel(QWidget):
    run_requested = Signal(str)
    http_run_requested = Signal(str, str, str, int)
    http_dry_run_requested = Signal(str)
    http_add_report_requested = Signal(str)
    vhost_run_requested = Signal(str, str, str, str)
    vhost_dry_run_requested = Signal(str)
    wildcard_detect_requested = Signal(str, str)
    enumerate_as_http_requested = Signal(str)
    vhost_validation_failed = Signal(str)
    smb_recon_requested = Signal(str)  # mode: full | null | guest | shares
    ftp_recon_requested = Signal(str, int)  # (mode: full | anon, port)
    ssh_recon_requested = Signal(int)  # port
    dns_recon_requested = Signal(str, int)  # (domain, port)
    ldap_recon_requested = Signal(str, int)  # (basedn, port)
    simple_recon_requested = Signal(str, int)  # (module name, discovered service port)

    def __init__(self) -> None:
        super().__init__()
        self._target = ""

        self._header = QLabel("No service selected.")
        self._header.setStyleSheet("font-weight: bold;")

        # generic page: tool hints + ad-hoc command
        self._hints = QListWidget()
        self._hints.itemClicked.connect(self._on_hint_activated)
        self._hints.itemActivated.connect(self._on_hint_activated)
        hints_box = QGroupBox("Tool hints (click to load — never auto-run)")
        QVBoxLayout(hints_box).addWidget(self._hints)
        self._command = QLineEdit()
        self._command.setPlaceholderText("select a tool hint above, or type a command")
        self._command.setAccessibleName("Command to run")
        self._run_button = QPushButton("Run")
        self._run_button.setAccessibleName("Run the command")
        self._run_button.clicked.connect(self._emit_run)
        self._copy_button = QPushButton("Copy")
        self._copy_button.setAccessibleName("Copy the command")
        self._copy_button.clicked.connect(self._copy_command)
        command_row = QHBoxLayout()
        command_row.addWidget(self._command, stretch=1)
        command_row.addWidget(self._run_button)
        command_row.addWidget(self._copy_button)
        generic = QWidget()
        generic_layout = QVBoxLayout(generic)
        generic_layout.addWidget(hints_box, stretch=1)
        generic_layout.addLayout(command_row)

        # web page: HTTP content-discovery builder + vhost builder in tabs
        self._http = HttpPanel()
        self._http.run_requested.connect(self.http_run_requested)
        self._http.dry_run_requested.connect(self.http_dry_run_requested)
        self._http.add_report_requested.connect(self.http_add_report_requested)
        self._vhost = VhostPanel()
        self._vhost.run_requested.connect(self.vhost_run_requested)
        self._vhost.dry_run_requested.connect(self.vhost_dry_run_requested)
        self._vhost.wildcard_detect_requested.connect(self.wildcard_detect_requested)
        self._vhost.enumerate_as_http_requested.connect(self.enumerate_as_http_requested)
        self._vhost.validation_failed.connect(self.vhost_validation_failed)
        self._web_tabs = QTabWidget()
        self._web_tabs.addTab(self._http, "Content discovery")
        self._web_tabs.addTab(self._vhost, "Vhosts")

        # smb page: Tier-1 recon buttons + Tier-2 manual follow-ups + findings
        self._smb = SmbPanel()
        self._smb.recon_requested.connect(self.smb_recon_requested)
        # Tier-2 follow-ups reuse the ad-hoc command path (validated at the shell chokepoint).
        self._smb.manual_requested.connect(self.run_requested)

        # ftp page: anonymous bounded-walk buttons + Tier-2 manual follow-ups + findings
        self._ftp = FtpPanel()
        self._ftp.recon_requested.connect(self.ftp_recon_requested)
        self._ftp.manual_requested.connect(self.run_requested)

        # ssh page: Tier-1 fingerprint button + Tier-2 manual follow-ups + findings
        self._ssh = SshPanel()
        self._ssh.recon_requested.connect(self.ssh_recon_requested)
        self._ssh.manual_requested.connect(self.run_requested)

        # dns page: Tier-1 protocol recon (+ domain field) + Tier-2 manual follow-ups + findings
        self._dns = DnsPanel()
        self._dns.recon_requested.connect(self.dns_recon_requested)
        self._dns.manual_requested.connect(self.run_requested)
        self._dns.validation_failed.connect(self.vhost_validation_failed)

        # ldap page: Tier-1 anonymous recon (+ base-DN field) + Tier-2 manual follow-ups + findings
        self._ldap = LdapPanel()
        self._ldap.recon_requested.connect(self.ldap_recon_requested)
        self._ldap.manual_requested.connect(self.run_requested)
        self._ldap.validation_failed.connect(self.vhost_validation_failed)

        # simple read-only modules share one panel type — one instance per module, keyed by name
        self._simple: dict[str, SimpleReconPanel] = {}
        for spec in SIMPLE_SPECS.values():
            panel = SimpleReconPanel(spec)
            panel.recon_requested.connect(self.simple_recon_requested)
            panel.manual_requested.connect(self.run_requested)
            self._simple[spec.module] = panel

        self._stack = QStackedWidget()
        self._stack.addWidget(generic)  # 0: generic hints
        self._stack.addWidget(self._web_tabs)  # 1: http/vhost builders
        self._stack.addWidget(self._smb)  # 2: smb
        self._stack.addWidget(self._ftp)  # 3: ftp
        self._stack.addWidget(self._ssh)  # 4: ssh
        self._stack.addWidget(self._dns)  # 5: dns
        self._stack.addWidget(self._ldap)  # 6: ldap
        for panel in self._simple.values():  # 7+: nfs/snmp/tftp/netbios/ike/ntp/smtp
            self._stack.addWidget(panel)

        # "Recon next steps" — pattern-library suggestions from findings (§15). Pre-fill only.
        self._next_steps = QListWidget()
        self._next_steps.setMaximumHeight(130)
        self._next_steps.itemActivated.connect(self._on_next_step_activated)
        next_box = QGroupBox(
            "Recon next steps (patterns — double-click to pre-fill; never auto-run)"
        )
        QVBoxLayout(next_box).addWidget(self._next_steps)
        self.set_suggestions([])

        self._banner = Banner()
        self._output = QPlainTextEdit()
        self._output.setReadOnly(True)
        self._output.setAccessibleName("Command output")

        # why: a QStackedWidget's minimum is the MAX over all pages, and wide builder pages (long
        # SimpleRecon intros, SMB/SSH forms) pushed that to ~1250px — which pinned the whole window
        # wide and unresizable. Scrolling the stack decouples that minimum; the window now shrinks
        # freely and the output/next-steps below stay always-visible.
        stack_scroll = QScrollArea()
        stack_scroll.setWidgetResizable(True)
        stack_scroll.setFrameShape(QFrame.Shape.NoFrame)
        stack_scroll.setWidget(self._stack)

        layout = QVBoxLayout(self)
        layout.addWidget(self._header)
        layout.addWidget(stack_scroll, stretch=2)
        layout.addWidget(next_box)
        layout.addWidget(self._banner)
        layout.addWidget(self._output, stretch=1)

    def set_theme(self, theme_name: str) -> None:
        self._banner.restyle(theme_name)

    def clear_banner(self) -> None:
        self._banner.clear()

    def set_target(self, target: str) -> None:
        self._target = target

    def set_profile(self, profile: Profile) -> None:
        self._http.set_profile(profile)
        self._vhost.set_profile(profile)
        self._smb.set_profile(profile)
        self._ftp.set_profile(profile)
        self._ssh.set_profile(profile)
        self._dns.set_profile(profile)
        self._ldap.set_profile(profile)
        for panel in self._simple.values():
            panel.set_profile(profile)

    def show_service(self, service: DiscoveredService | None, ref: ServiceRef | None) -> None:
        self._hints.clear()
        if service is None:
            self._header.setText("No service selected.")
            self._stack.setCurrentIndex(0)
            return
        label = ref.label if ref is not None else service.service
        self._header.setText(f"{service.port}/{service.proto.value} — {label}")
        if ref is not None and ref.module == "http":
            self._http.configure(service, ref)
            self._vhost.configure(service)
            self._stack.setCurrentWidget(self._web_tabs)
            return
        if ref is not None and ref.module == "smb":
            self._smb.configure(service)
            self._stack.setCurrentWidget(self._smb)
            return
        if ref is not None and ref.module == "ftp":
            self._ftp.configure(service)
            self._stack.setCurrentWidget(self._ftp)
            return
        if ref is not None and ref.module == "ssh":
            self._ssh.configure(service)
            self._stack.setCurrentWidget(self._ssh)
            return
        if ref is not None and ref.module == "dns":
            self._dns.configure(service)
            self._stack.setCurrentWidget(self._dns)
            return
        if ref is not None and ref.module == "ldap":
            self._ldap.configure(service)
            self._stack.setCurrentWidget(self._ldap)
            return
        if ref is not None and ref.module in self._simple:
            panel = self._simple[ref.module]
            panel.configure(service)
            self._stack.setCurrentWidget(panel)
            return
        self._stack.setCurrentIndex(0)
        if ref is None:
            return
        for hint in ref.tools:
            expanded = expand_hint(
                hint.name, target=self._target, port=service.port, proto=service.proto.value
            )
            item = QListWidgetItem(f"{expanded}\n    {hint.purpose}")
            item.setData(_COMMAND_ROLE, expanded)
            self._hints.addItem(item)

    def set_running(self, running: bool) -> None:
        # why: the http/vhost builders persist into the shared Profile on every control change;
        # disable them during a scan so a UI edit can't race the worker thread's profile.save().
        self._run_button.setEnabled(not running)
        self._http.setEnabled(not running)
        self._vhost.setEnabled(not running)
        self._smb.set_running(running)
        self._ftp.set_running(running)
        self._ssh.set_running(running)
        self._dns.set_running(running)
        self._ldap.set_running(running)
        for panel in self._simple.values():
            panel.set_running(running)

    def set_smb_summary(self, lines: list[str]) -> None:
        self._smb.set_summary(lines)

    def set_ftp_summary(self, lines: list[str]) -> None:
        self._ftp.set_summary(lines)

    def set_ssh_summary(self, lines: list[str]) -> None:
        self._ssh.set_summary(lines)

    def set_dns_summary(self, lines: list[str]) -> None:
        self._dns.set_summary(lines)

    def set_ldap_summary(self, lines: list[str]) -> None:
        self._ldap.set_summary(lines)

    def set_simple_summary(self, module: str, lines: list[str]) -> None:
        panel = self._simple.get(module)
        if panel is not None:
            panel.set_summary(lines)

    def set_suggestions(self, suggestions: list[Suggestion]) -> None:
        self._next_steps.clear()
        if not suggestions:
            placeholder = QListWidgetItem("No pattern suggestions yet.")
            placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
            self._next_steps.addItem(placeholder)
            return
        for suggestion in suggestions:
            label = suggestion.text
            source = suggestion.source_box or suggestion.source_pattern
            if source:
                label += f"\n    ↳ source: {source}"
            if suggestion.command_template:
                label += f"\n    $ {suggestion.command_template}  (double-click to pre-fill)"
            item = QListWidgetItem(label)
            if suggestion.command_template:
                item.setData(_COMMAND_ROLE, suggestion.command_template)
            self._next_steps.addItem(item)

    def _on_next_step_activated(self, item: QListWidgetItem) -> None:
        command = item.data(_COMMAND_ROLE)
        if isinstance(command, str) and command:
            # pre-fill the command builder (never auto-run) and surface it
            self._command.setText(command)
            self._stack.setCurrentIndex(0)

    def add_vhosts(self, vhosts: list[str]) -> None:
        self._vhost.add_vhosts(vhosts)

    def set_vhost_filter_size(self, size: int) -> None:
        self._vhost.set_filter_size(size)

    def enumerate_http(self, vhost: str) -> None:
        self._http.set_url(f"http://{vhost}/")
        self._web_tabs.setCurrentWidget(self._http)
        self._stack.setCurrentWidget(self._web_tabs)

    def append_output(self, text: str) -> None:
        self._output.appendPlainText(text)
        match = _TAG_RE.match(text.strip())
        if match is not None:
            kind = _TAG_KIND.get(match.group(1))
            if kind is not None:  # surface actionable outcomes; leave info-level chatter in the log
                self._banner.show_message(kind, text.strip())

    def clear_output(self) -> None:
        self._output.clear()

    def _on_hint_activated(self, item: QListWidgetItem) -> None:
        command = item.data(_COMMAND_ROLE)
        if isinstance(command, str):
            self._command.setText(command)

    def prefill_command(self, command: str) -> None:
        # why: external callers (Scan -> Nmap presets) drop a command into the generic builder for
        # the user to review + Run; switch to the generic page so it's visible. Never auto-runs.
        self._command.setText(command)
        self._stack.setCurrentIndex(0)

    def _emit_run(self) -> None:
        command = self._command.text().strip()
        if command:
            self.run_requested.emit(command)

    def _copy_command(self) -> None:
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(self._command.text())
