from __future__ import annotations

import re

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
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
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from oscprecon import nse_profiles
from oscprecon.gui.simple_recon import SIMPLE_SPECS
from oscprecon.gui.theme import tokens
from oscprecon.gui.widgets.banner import Banner
from oscprecon.gui.widgets.discovered_urls_panel import DiscoveredUrlsPanel
from oscprecon.gui.widgets.dns_panel import DnsPanel
from oscprecon.gui.widgets.ftp_panel import FtpPanel
from oscprecon.gui.widgets.http_panel import HttpPanel
from oscprecon.gui.widgets.ldap_panel import LdapPanel
from oscprecon.gui.widgets.simple_recon_panel import SimpleReconPanel
from oscprecon.gui.widgets.smb_panel import SmbPanel
from oscprecon.gui.widgets.ssh_panel import SshPanel
from oscprecon.gui.widgets.vhost_panel import VhostPanel
from oscprecon.models import DiscoveredService, Proto, Suggestion
from oscprecon.profile import Profile
from oscprecon.references import ServiceRef, expand_hint

_COMMAND_ROLE = Qt.ItemDataRole.UserRole

# the six escalating scan profiles (nse_profiles) — version → safe enum → vuln → auth → brute →
# intrusive. Built from the service's own script prefixes, so each one is service-specific.
_MODE_ORDER: tuple[str, ...] = nse_profiles.MODES


class _CurrentPageStack(QStackedWidget):
    # why: a QStackedWidget reserves the MAX size over ALL pages, so the tool panel always demanded
    # the tallest/widest builder's footprint even when showing a small one. Size to the VISIBLE page
    # so short panels stay compact and the surrounding scroll area only scrolls when truly needed.
    def __init__(self) -> None:
        super().__init__()
        self.currentChanged.connect(lambda _index: self.updateGeometry())

    def sizeHint(self) -> QSize:
        widget = self.currentWidget()
        return widget.sizeHint() if widget is not None else super().sizeHint()

    def minimumSizeHint(self) -> QSize:
        widget = self.currentWidget()
        return widget.minimumSizeHint() if widget is not None else super().minimumSizeHint()


# leading [tag] on a status line -> banner kind. Untagged lines (raw tool output) never touch the
# banner. Only actionable/outcome tags surface; info chatter (running/dry-run) stays in the log.
_TAG_RE = re.compile(r"^\[([a-z][a-z-]*)\]")
_TAG_KIND = {
    "vuln": "error",  # a VULNERABLE verdict is the loudest thing recon can say
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
    # (service name, port, mode, proto, host_ip). proto matters: a UDP service scanned over TCP
    # comes back "clean" and the operator believes it. host_ip aims it at a PIVOTED host, not the
    # entry box — every other panel already receives it.
    vuln_scan_requested = Signal(str, int, str, str, str)

    def __init__(self) -> None:
        super().__init__()
        self._target = ""
        self._multi = False  # >1 task running -> prefix streamed lines with the run's tag
        self._service: DiscoveredService | None = None
        self._service_host_ip = ""  # set when the selected service belongs to a PIVOTED host
        self._discovered: list[DiscoveredService] = []  # for the vuln row's family-port preview

        self._header = QLabel(
            "No service selected — run Recon, then pick a service to build its commands."
        )
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
        self._http.manual_requested.connect(self.run_requested)  # Tier-2 follow-ups (WebDAV, …)
        self._http.notice.connect(self.append_output)  # unresolved-hostname warning, etc.
        self._vhost = VhostPanel()
        self._vhost.run_requested.connect(self.vhost_run_requested)
        self._vhost.dry_run_requested.connect(self.vhost_dry_run_requested)
        self._vhost.wildcard_detect_requested.connect(self.wildcard_detect_requested)
        self._vhost.enumerate_as_http_requested.connect(self.enumerate_as_http_requested)
        self._vhost.validation_failed.connect(self.vhost_validation_failed)
        self._urls = DiscoveredUrlsPanel()
        self._web_tabs = QTabWidget()
        self._web_tabs.addTab(self._http, "Content discovery")
        self._web_tabs.addTab(self._urls, "Discovered URLs")
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

        self._vuln_row = self._build_vuln_row()

        self._stack = _CurrentPageStack()
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
        # Collapsible: on a service with a lot of suggestions this box crowded out the builder, and
        # a fixed 130px cap meant it could be neither read properly nor got out of the way.
        self._next_steps = QListWidget()
        self._next_steps.setMinimumHeight(60)
        self._next_steps.itemActivated.connect(self._on_next_step_activated)
        self._next_box = QGroupBox("Recon next steps")
        next_layout = QVBoxLayout(self._next_box)
        next_layout.setContentsMargins(tokens.SPACE_SM, tokens.SPACE_SM, tokens.SPACE_SM, 0)
        self._next_hint = QLabel("patterns — double-click to pre-fill; never auto-run")
        self._next_hint.setObjectName("hintText")
        next_layout.addWidget(self._next_hint)
        next_layout.addWidget(self._next_steps)
        self._next_toggle = QToolButton()
        self._next_toggle.setText("▾")
        self._next_toggle.setAutoRaise(True)
        self._next_toggle.setToolTip("Collapse / expand the next-steps list")
        self._next_toggle.setAccessibleName("Collapse next steps")
        self._next_toggle.clicked.connect(self._toggle_next_steps)
        self._next_box_collapsed = False
        self.set_suggestions([])

        self._banner = Banner()
        self._output = QPlainTextEdit()
        self._output.setReadOnly(True)
        self._output.setAccessibleName("Command output")

        # why: the three regions of this column — the builder, the suggestions, and the live
        # output — compete for the same vertical space, and which one you need is entirely
        # situational: a wide SMB builder while configuring, the output while a scan streams, the
        # suggestions while deciding what is next. A fixed split served none of them, so they sit in
        # a DRAGGABLE splitter; the builder still scrolls internally (so its Run button is never cut
        # off on a short window) and the suggestions collapse to their title bar with one click.
        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.addWidget(self._header)
        body_layout.addWidget(self._vuln_row)
        body_layout.addWidget(self._stack, stretch=1)

        body_scroll = QScrollArea()
        body_scroll.setWidgetResizable(True)
        body_scroll.setFrameShape(QFrame.Shape.NoFrame)
        body_scroll.setWidget(body)

        next_header = QWidget()
        next_row = QHBoxLayout(next_header)
        next_row.setContentsMargins(0, 0, 0, 0)
        next_row.addWidget(self._next_toggle)
        next_row.addWidget(self._next_box, stretch=1)

        self._split = QSplitter(Qt.Orientation.Vertical)
        self._split.setChildrenCollapsible(True)
        self._split.addWidget(body_scroll)
        self._split.addWidget(next_header)
        self._split.addWidget(self._output)
        self._split.setStretchFactor(0, 3)
        self._split.setStretchFactor(1, 1)
        self._split.setStretchFactor(2, 3)
        self._split.setSizes([420, 150, 300])

        self._output.setMinimumHeight(80)

        layout = QVBoxLayout(self)
        layout.addWidget(self._split, stretch=1)
        layout.addWidget(self._banner)

    def _toggle_next_steps(self) -> None:
        self._next_box_collapsed = not self._next_box_collapsed
        self._next_steps.setVisible(not self._next_box_collapsed)
        self._next_hint.setVisible(not self._next_box_collapsed)
        self._next_toggle.setText("▸" if self._next_box_collapsed else "▾")
        self._next_toggle.setToolTip(
            "Expand the next-steps list" if self._next_box_collapsed else "Collapse it"
        )

    def set_theme(self, theme_name: str) -> None:
        self._banner.restyle(theme_name)
        self._urls.set_theme(theme_name)

    def refresh_discovered_urls(self) -> None:
        # called after a content-discovery run parses new findings, so the URL table grows live
        self._urls.refresh()

    def clear_banner(self) -> None:
        self._banner.clear()

    def set_target(self, target: str) -> None:
        self._target = target

    def set_profile(self, profile: Profile) -> None:
        self._discovered = list(profile.discovered_services)
        self._http.set_profile(profile)
        self._urls.set_profile(profile)
        self._vhost.set_profile(profile)
        self._smb.set_profile(profile)
        self._ftp.set_profile(profile)
        self._ssh.set_profile(profile)
        self._dns.set_profile(profile)
        self._ldap.set_profile(profile)
        for panel in self._simple.values():
            panel.set_profile(profile)

    def show_service(
        self, service: DiscoveredService | None, ref: ServiceRef | None, host_ip: str = ""
    ) -> None:
        # host_ip != "" when the service belongs to a PIVOTED host — every panel then targets that
        # host instead of the entry box (else feroxbuster/smb/etc. would recon the wrong machine).
        self._hints.clear()
        self._service = service
        self._service_host_ip = host_ip
        self._sync_vuln_row(service)
        if service is None:
            self._header.setText(
                "No service selected — run Recon, then pick a service to build its commands."
            )
            self._stack.setCurrentIndex(0)
            return
        label = ref.label if ref is not None else service.service
        pivot = f"  ·  pivot host {host_ip}" if host_ip else ""
        self._header.setText(f"{service.port}/{service.proto.value} — {label}{pivot}")
        if ref is not None and ref.module == "http":
            self._http.configure(service, ref, host_ip)
            self._urls.configure(service, host_ip)
            self._vhost.configure(service, host_ip)
            self._stack.setCurrentWidget(self._web_tabs)
            return
        if ref is not None and ref.module == "smb":
            self._smb.configure(service, host_ip)
            self._stack.setCurrentWidget(self._smb)
            return
        if ref is not None and ref.module == "ftp":
            self._ftp.configure(service, host_ip)
            self._stack.setCurrentWidget(self._ftp)
            return
        if ref is not None and ref.module == "ssh":
            self._ssh.configure(service, host_ip)
            self._stack.setCurrentWidget(self._ssh)
            return
        if ref is not None and ref.module == "dns":
            self._dns.configure(service, host_ip)
            self._stack.setCurrentWidget(self._dns)
            return
        if ref is not None and ref.module == "ldap":
            self._ldap.configure(service, host_ip)
            self._stack.setCurrentWidget(self._ldap)
            return
        if ref is not None and ref.module in self._simple:
            panel = self._simple[ref.module]
            panel.configure(service, host_ip)
            self._stack.setCurrentWidget(panel)
            return
        self._stack.setCurrentIndex(0)
        if ref is None:
            return
        for hint in ref.tools:
            expanded = expand_hint(
                hint.name,
                target=host_ip or self._target,
                port=service.port,
                proto=service.proto.value,
            )
            item = QListWidgetItem(f"{expanded}\n    {hint.purpose}")
            item.setData(_COMMAND_ROLE, expanded)
            self._hints.addItem(item)

    def _build_vuln_row(self) -> QWidget:
        # Present for EVERY service, above whichever builder is showing. The driving miss: a box
        # whose only way in was an `smb-vuln-*` NSE check that the tool never offered, on a service
        # panel that had five other buttons. Now every service has its vuln checks one click away.
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        self._vuln_button = QPushButton("⚠  NSE scripts")
        self._vuln_button.setAccessibleName("Run NSE vuln scripts against this service")
        self._vuln_button.clicked.connect(self._emit_vuln_scan)
        self._vuln_mode = QComboBox()
        self._vuln_mode.setMinimumWidth(210)
        self._vuln_mode.setAccessibleName("NSE scan profile")
        for mode in _MODE_ORDER:
            spec = nse_profiles.MODE_SPECS[mode]
            self._vuln_mode.addItem(spec.label, mode)
        # default to the vulnerability profile: this control exists because a missed `smb-vuln-*`
        # cost an operator a box. The cheaper profiles are one click away in the dropdown.
        self._vuln_mode.setCurrentIndex(_MODE_ORDER.index(nse_profiles.MODE_VULN))
        self._vuln_mode.currentIndexChanged.connect(lambda _i: self._sync_vuln_row(self._service))
        self._vuln_hint = QLabel("")
        self._vuln_hint.setWordWrap(True)
        layout.addWidget(self._vuln_button)
        layout.addWidget(self._vuln_mode)
        layout.addWidget(self._vuln_hint, stretch=1)
        return row

    def _family_ports(self, service: DiscoveredService, prefixes: tuple[str, ...]) -> list[int]:
        # what the scan will actually cover: every open port of this service family on this box, so
        # 139 AND 445 go in one pass. The tooltip must show THAT command, not a one-port
        # approximation of it.
        same = [
            s.port
            for s in self._discovered
            if s.state == "open"
            and s.proto is service.proto
            and nse_profiles.for_service(s.service, s.port, s.product)[1] == prefixes
        ]
        return sorted(set(same) | {service.port})

    def _sync_vuln_row(self, service: DiscoveredService | None) -> None:
        if service is None:
            self._vuln_row.setVisible(False)
            return
        self._vuln_row.setVisible(True)
        label, prefixes, _declared = nse_profiles.for_service(
            service.service, service.port, service.product
        )
        mode = str(self._vuln_mode.currentData() or nse_profiles.MODE_ENUM)
        spec = nse_profiles.MODE_SPECS[mode]
        udp = service.proto is not Proto.TCP
        # PREVIEW what will run, before it runs — the operator's own rule about wildcards. This is
        # the same evaluation the policy gate uses, so the count is what nmap will actually select.
        scripts = nse_profiles.preview(prefixes, mode)
        if mode == nse_profiles.MODE_VERSION:
            self._vuln_hint.setText(f"{label} · -sV --version-all (no scripts)")
        elif scripts:
            self._vuln_hint.setText(f"{label} · {len(scripts)} script(s) — {spec.label.lower()}")
        else:
            self._vuln_hint.setText(f"{label} · no scripts match this profile for this service")
        gate = nse_profiles.gate_for(mode)
        warn = ""
        if gate == "spray":
            warn = "\n\n⚠ Credential brute — runs only in opt-in Spray mode (§2a)."
        elif gate == "dangerous":
            warn = "\n\n⚠ Can crash the service or change state on it. Confirms before running."
        preview = "\n  ".join(scripts[:14]) + ("\n  …" if len(scripts) > 14 else "")
        self._vuln_button.setToolTip(
            f"{spec.why}{warn}\n\nRuns: "
            + nse_profiles.build_command(
                self._service_host_ip or "<target>",
                tuple(self._family_ports(service, prefixes)),
                prefixes,
                mode,
                proto=service.proto,
            )
            + ("\n\n-sU needs root — run Nabu with sudo, or the scan finds nothing." if udp else "")
            + (f"\n\nSelects:\n  {preview}" if scripts else "")
        )

    def _emit_vuln_scan(self) -> None:
        if self._service is None:
            return
        mode = str(self._vuln_mode.currentData() or nse_profiles.MODE_ENUM)
        self.vuln_scan_requested.emit(
            self._service.service,
            self._service.port,
            mode,
            self._service.proto.value,
            self._service_host_ip,
        )

    def set_running(self, running: bool) -> None:
        # why: the http/vhost builders persist into the shared Profile on every control change;
        # disable them during a scan so a UI edit can't race the worker thread's profile.save().
        self._run_button.setEnabled(not running)
        self._vuln_button.setEnabled(not running)
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

    def enumerate_http(self, vhost: str, base_url: str = "") -> None:
        # `base_url` carries the scheme + port of the web service the vhost was found on; without it
        # this hardcoded http://…:80, which is the wrong port (and often closed) on an 8443 box.
        self._http.set_url(base_url or f"http://{vhost}/")
        self._web_tabs.setCurrentWidget(self._http)
        self._stack.setCurrentWidget(self._web_tabs)

    def set_multi(self, multi: bool) -> None:
        # why: with several scans streaming into one pane, interleaved lines are unreadable unless
        # each one says which run it came from. Only prefix while >1 task runs — a single scan's
        # output stays exactly as it always was.
        self._multi = multi

    def append_output(self, text: str, tag: str = "") -> None:
        self._output.appendPlainText(f"{tag} │ {text}" if (self._multi and tag) else text)
        # the banner matches on the UNTAGGED text so [blocked]/[done]/[vuln] still surface when
        # several scans are running.
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
