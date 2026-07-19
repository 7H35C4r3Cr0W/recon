from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSlider,
    QSpinBox,
    QSplitter,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

from oscprecon import manual_commands
from oscprecon.gui.theme import styles
from oscprecon.gui.widgets.wordlist_picker import WordlistPicker
from oscprecon.models import DiscoveredService
from oscprecon.modules import http as http_mod
from oscprecon.modules.http import (
    EXTENSION_PRESETS,
    STATUS_PRESETS,
    HttpScanSettings,
    build_command,
    default_output,
    default_url,
    is_tls,
    wide_net_extensions,
)
from oscprecon.profile import Profile
from oscprecon.references import ServiceRef

_MANUAL_YAML = (
    Path(http_mod.__file__).parent / "manual_commands.yaml" if http_mod.__file__ else None
)
_MANUAL_ROLE = Qt.ItemDataRole.UserRole
_DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/big.txt"
_TOOL_LABELS = {
    "feroxbuster": "feroxbuster",
    "gobuster dir": "gobuster",
    "ffuf": "ffuf",
    "dirsearch": "dirsearch",
}


def _port_from_url(url: str) -> int:
    # the effective port for a URL: an explicit :port, else 443 for https / 80 for http
    parts = urlsplit(url if "//" in url else f"//{url}")
    if parts.port:
        return parts.port
    return 443 if parts.scheme == "https" else 80


class HttpPanel(QWidget):
    run_requested = Signal(str, str, str, int)  # command, output_rel, tool, port
    dry_run_requested = Signal(str)
    add_report_requested = Signal(str)
    manual_requested = Signal(str)  # a Tier-2 follow-up command (WebDAV, endpoints, methods)

    def __init__(self) -> None:
        super().__init__()
        self._profile: Profile | None = None
        self._manual_entries = (
            manual_commands.load_manual_commands(_MANUAL_YAML) if _MANUAL_YAML else []
        )
        self._port = 80
        self._wordlist = _DEFAULT_WORDLIST
        self._output_is_custom = False
        self._loading = False

        self._tool = QComboBox()
        self._tool.addItems(list(_TOOL_LABELS))
        self._url = QLineEdit()
        self._wordlist_label = QLabel(self._wordlist)
        self._wordlist_label.setWordWrap(True)
        choose = QPushButton("Choose…")
        choose.clicked.connect(self._choose_wordlist)
        wl_row = QHBoxLayout()
        wl_row.addWidget(self._wordlist_label, stretch=1)
        wl_row.addWidget(choose)

        # why: extensions default OFF (CLAUDE.md §9). "Wide net" is 60+ extensions; with the default
        # big.txt (~20k words) it fires ~1.2M requests — far too slow/noisy for a first pass and it
        # never finishes on the exam clock. A wordlist-only pass still finds files whose names are
        # in the list (e.g. admin.php); opt into -x extensions deliberately once a stack is known.
        self._wide_net = QCheckBox("Wide net (all extensions — slow)")
        self._wide_net.setChecked(False)
        self._group_boxes: dict[str, QCheckBox] = {}
        ext_grid = QGridLayout()
        ext_grid.addWidget(self._wide_net, 0, 0, 1, 2)
        for index, group in enumerate(EXTENSION_PRESETS):
            box = QCheckBox(group)
            self._group_boxes[group] = box
            ext_grid.addWidget(box, 1 + index // 2, index % 2)
        self._custom_exts = QLineEdit()
        self._custom_exts.setPlaceholderText("custom extensions, comma or space separated")
        ext_box = QGroupBox("Extensions")
        ext_layout = QVBoxLayout(ext_box)
        ext_layout.addLayout(ext_grid)
        ext_layout.addWidget(self._custom_exts)

        self._threads = QSlider(Qt.Orientation.Horizontal)
        self._threads.setRange(1, 200)
        self._threads.setValue(40)
        self._threads_label = QLabel()
        self._depth = QSlider(Qt.Orientation.Horizontal)
        self._depth.setRange(0, 10)
        self._depth.setValue(2)
        self._depth_label = QLabel()
        self._timeout = QSpinBox()
        self._timeout.setRange(1, 120)
        self._timeout.setValue(10)
        self._rate_enabled = QCheckBox("rate limit")
        self._rate = QSpinBox()
        self._rate.setRange(1, 1000)
        self._rate.setValue(40)
        self._rate.setEnabled(False)
        rate_row = QHBoxLayout()
        rate_row.addWidget(self._rate_enabled)
        rate_row.addWidget(self._rate)
        self._skip_tls = QCheckBox("skip TLS verify (-k)")
        self._skip_tls.setChecked(True)
        self._status_preset = QComboBox()
        self._status_preset.addItems([*STATUS_PRESETS, "Custom"])
        self._status_preset.setCurrentText("All informative")
        self._status_csv = QLineEdit(",".join(str(c) for c in STATUS_PRESETS["All informative"]))
        self._output = QLineEdit()

        form = QFormLayout()
        form.addRow("Tool:", self._tool)
        form.addRow("Target URL:", self._url)
        form.addRow("Wordlist:", self._wrap(wl_row))
        form.addRow("Threads:", self._with_label(self._threads, self._threads_label))
        form.addRow("Recursion depth:", self._with_label(self._depth, self._depth_label))
        form.addRow("Timeout (s):", self._timeout)
        form.addRow("Rate:", self._wrap(rate_row))
        form.addRow("", self._skip_tls)
        form.addRow("Status codes:", self._status_preset)
        form.addRow("", self._status_csv)
        form.addRow("Output file:", self._output)

        self._preview = QPlainTextEdit()
        self._preview.setReadOnly(True)
        self._preview.setMinimumHeight(48)  # a floor; the splitter sizes it from here up
        fingerprint = QPushButton("Fingerprint")
        fingerprint.setToolTip(
            "Run whatweb and record the stack fingerprint (server, title, versions) as findings"
        )
        fingerprint.clicked.connect(self._on_fingerprint)
        run = QPushButton("Run")
        run.setStyleSheet(styles.accent_button())  # primary content-discovery action
        run.clicked.connect(self._on_run)
        self._run_btn = run
        dry = QPushButton("Dry-run")
        dry.clicked.connect(self._on_dry_run)
        report = QPushButton("Add to report")
        report.clicked.connect(self._on_add_report)
        button_row = QHBoxLayout()
        button_row.addWidget(fingerprint)
        button_row.addWidget(run)
        button_row.addWidget(dry)
        button_row.addWidget(report)
        button_row.addStretch(1)

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.addLayout(form)
        inner_layout.addWidget(ext_box)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(inner)

        # command preview + action buttons — kept together and NON-collapsible so Run is always
        # reachable even when the form and follow-ups panes are dragged shut.
        preview_pane = QWidget()
        preview_layout = QVBoxLayout(preview_pane)
        preview_layout.setContentsMargins(0, 0, 0, 0)
        preview_layout.addWidget(QLabel("Command preview:"))
        preview_layout.addWidget(self._preview, stretch=1)
        preview_layout.addLayout(button_row)

        # Tier-2 follow-ups (WebDAV OPTIONS/PROPFIND/nmap-webdav-scan, endpoint + method probes) —
        # shown, run on double-click through the shell chokepoint like the FTP/SSH/DNS panels.
        self._manual = QListWidget()
        self._manual.itemActivated.connect(self._on_manual_activated)
        self._manual.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._manual.customContextMenuRequested.connect(self._on_manual_menu)
        manual_box = QGroupBox(
            "Manual follow-ups (Tier 2 — double-click to run; WebDAV, endpoints)"
        )
        QVBoxLayout(manual_box).addWidget(self._manual)

        # a vertical splitter so the three regions (settings form · command preview · follow-ups)
        # are drag-resizable — the form/follow-ups can be collapsed to give the other panes room,
        # fixing the old cramped, unresizable stack of fixed-height widgets.
        self._split = QSplitter(Qt.Orientation.Vertical)
        self._split.addWidget(scroll)
        self._split.addWidget(preview_pane)
        self._split.addWidget(manual_box)
        self._split.setCollapsible(0, True)  # form can be tucked away
        self._split.setCollapsible(1, False)  # keep the preview + Run visible
        self._split.setCollapsible(2, True)  # follow-ups can be tucked away
        self._split.setStretchFactor(0, 5)
        self._split.setStretchFactor(1, 2)
        self._split.setStretchFactor(2, 2)
        self._split.setSizes([420, 150, 130])

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._split)

        self._connect_signals()
        self._refresh()

    def _reload_manual(self) -> None:
        self._manual.clear()
        if self._profile is None:
            return
        target = self._profile.target
        for entry in self._manual_entries:
            command = manual_commands.expand(
                entry.command,
                target=target.ip,
                port=self._port,
                url=self._url.text(),
                domain=target.hostname or "",
            )
            item = QListWidgetItem(f"{entry.description}\n    {command}")
            item.setData(_MANUAL_ROLE, command)
            self._manual.addItem(item)

    def _on_manual_activated(self, item: QListWidgetItem) -> None:
        command = item.data(_MANUAL_ROLE)
        if isinstance(command, str):
            self.manual_requested.emit(command)

    def _on_manual_menu(self, pos: QPoint) -> None:
        item = self._manual.currentItem()
        viewport = self._manual.viewport()
        if item is None or viewport is None:
            return
        command = item.data(_MANUAL_ROLE)
        if not isinstance(command, str):
            return
        menu = QMenu(self)
        if menu.addAction("Copy command") == menu.exec(viewport.mapToGlobal(pos)):
            clipboard = QGuiApplication.clipboard()
            if clipboard is not None:
                clipboard.setText(command)

    @staticmethod
    def _wrap(inner: Any) -> QWidget:
        widget = QWidget()
        widget.setLayout(inner)
        return widget

    @staticmethod
    def _with_label(slider: QSlider, label: QLabel) -> QWidget:
        widget = QWidget()
        row = QHBoxLayout(widget)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(slider, stretch=1)
        row.addWidget(label)
        return widget

    def _connect_signals(self) -> None:
        self._tool.currentTextChanged.connect(self._refresh)
        self._url.textChanged.connect(self._refresh)
        self._url.textChanged.connect(self._reload_manual)  # follow-ups embed the current {url}
        self._custom_exts.textChanged.connect(self._refresh)
        self._threads.valueChanged.connect(self._refresh)
        self._depth.valueChanged.connect(self._refresh)
        self._timeout.valueChanged.connect(self._refresh)
        self._rate.valueChanged.connect(self._refresh)
        self._rate_enabled.toggled.connect(self._on_rate_toggled)
        self._skip_tls.toggled.connect(self._refresh)
        self._status_csv.textChanged.connect(self._refresh)
        self._status_csv.textChanged.connect(
            self._sync_status_combo
        )  # keep the preset combo honest
        self._status_preset.currentTextChanged.connect(self._on_status_preset)
        self._output.textChanged.connect(self._on_output_changed)
        self._wide_net.toggled.connect(self._refresh)
        for box in self._group_boxes.values():
            box.toggled.connect(self._refresh)

    def set_profile(self, profile: Profile) -> None:
        self._profile = profile
        self._apply_settings(profile.module_settings.get("http", {}))
        self._reload_manual()

    def configure(self, service: DiscoveredService, ref: ServiceRef, host_ip: str = "") -> None:
        self._port = service.port
        tls = is_tls(service.service, service.port)
        if host_ip:  # a pivoted host — target its IP, not the entry box (no hostname for it)
            host = host_ip
        else:
            host = self._profile.target.ip if self._profile is not None else ""
            if self._profile is not None and self._profile.target.hostname:
                host = self._profile.target.hostname
        self._url.setText(default_url(host, service.port, tls))
        self._output_is_custom = False  # a new port re-derives the default output path
        self._refresh()
        self._reload_manual()

    def set_url(self, url: str) -> None:
        self._url.setText(url)
        # re-derive the port from the URL so the default output path lands under the NEW target's
        # subtree — else a vhost enumerated from an 8443 selection would file its port-80 scan under
        # http/8443/ (the stale _port). [#36]
        self._port = _port_from_url(url)
        self._output_is_custom = False
        self._refresh()

    def _on_rate_toggled(self, enabled: bool) -> None:
        self._rate.setEnabled(enabled)
        self._refresh()

    def _on_status_preset(self, name: str) -> None:
        if name in STATUS_PRESETS:
            self._status_csv.setText(",".join(str(c) for c in STATUS_PRESETS[name]))
        self._refresh()

    def _sync_status_combo(self) -> None:
        # keep the preset dropdown honest: after a profile load or a hand-edited CSV, show the
        # preset whose codes match, else "Custom" — so the combo never misrepresents the status set.
        current = [t for t in re.split(r"[,\s]+", self._status_csv.text().strip()) if t]
        match = "Custom"
        for preset_name, codes in STATUS_PRESETS.items():
            if [str(c) for c in codes] == current:
                match = preset_name
                break
        self._status_preset.blockSignals(True)  # setting text must not re-fire _on_status_preset
        self._status_preset.setCurrentText(match)
        self._status_preset.blockSignals(False)

    def _choose_wordlist(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("Choose wordlist")
        dialog.resize(640, 460)
        picker = WordlistPicker()
        picker.wordlist_chosen.connect(lambda path: self._set_wordlist(path, dialog))
        QVBoxLayout(dialog).addWidget(picker)
        try:
            dialog.exec()
        finally:
            picker.shutdown()

    def _set_wordlist(self, path: str, dialog: QDialog) -> None:
        self._wordlist = path
        self._wordlist_label.setText(path)
        dialog.accept()
        self._refresh()

    def _current_extensions(self) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []

        def add(items: list[str]) -> None:
            for item in items:
                if item and item not in seen:
                    seen.add(item)
                    result.append(item)

        if self._wide_net.isChecked():
            add(wide_net_extensions())
        for group, box in self._group_boxes.items():
            if box.isChecked():
                add(EXTENSION_PRESETS[group])
        add([e for e in re.split(r"[,\s]+", self._custom_exts.text().strip()) if e])
        return result

    def _current_status_codes(self) -> list[int]:
        codes: list[int] = []
        for token in re.split(r"[,\s]+", self._status_csv.text().strip()):
            if token.isdigit():
                codes.append(int(token))
        return codes

    def _current_settings(self) -> HttpScanSettings:
        return HttpScanSettings(
            tool=_TOOL_LABELS[self._tool.currentText()],
            url=self._url.text().strip(),
            wordlist=self._wordlist,
            extensions=self._current_extensions(),
            threads=self._threads.value(),
            depth=self._depth.value(),
            timeout=self._timeout.value(),
            rate_limit=self._rate.value() if self._rate_enabled.isChecked() else None,
            skip_tls=self._skip_tls.isChecked(),
            status_codes=self._current_status_codes(),
            output_file=self._output.text().strip(),
        )

    def _refresh(self) -> None:
        if self._loading:
            return
        tool = _TOOL_LABELS[self._tool.currentText()]
        if not self._output_is_custom:
            self._loading = True
            self._output.setText(default_output(self._port, tool, self._wordlist))
            self._loading = False

        self._threads_label.setText(
            f"{self._threads.value()}" + ("  ⚠ noisy" if self._threads.value() > 100 else "")
        )
        self._depth_label.setText(
            f"{self._depth.value()}" + ("  ⚠ slow" if self._depth.value() > 4 else "")
        )
        self._preview.setPlainText(build_command(self._current_settings()))
        self._save_only()

    def _save_only(self) -> None:
        if self._profile is None or self._loading:
            return
        self._profile.module_settings["http"] = {
            "tool": self._tool.currentText(),
            "wordlist": self._wordlist,
            "threads": self._threads.value(),
            "depth": self._depth.value(),
            "timeout": self._timeout.value(),
            "rate_enabled": self._rate_enabled.isChecked(),
            "rate": self._rate.value(),
            "skip_tls": self._skip_tls.isChecked(),
            "status_csv": self._status_csv.text(),
            "custom_exts": self._custom_exts.text(),
            "wide_net": self._wide_net.isChecked(),
            "groups": [g for g, b in self._group_boxes.items() if b.isChecked()],
        }
        # note: 'output' is intentionally not persisted — it is always re-derived per port/tool/
        # wordlist; a user edit sticks within the session via self._output_is_custom.

    def _on_output_changed(self) -> None:
        if not self._loading:
            self._output_is_custom = True  # a user edit sticks; the default no longer overwrites it
        self._save_only()

    def _apply_settings(self, data: dict[str, Any]) -> None:
        if not data:
            return
        self._loading = True
        if isinstance(data.get("tool"), str) and data["tool"] in _TOOL_LABELS:
            self._tool.setCurrentText(data["tool"])
        if isinstance(data.get("wordlist"), str) and data["wordlist"]:
            self._wordlist = data["wordlist"]
            self._wordlist_label.setText(self._wordlist)
        for key, widget in (
            ("threads", self._threads),
            ("depth", self._depth),
            ("timeout", self._timeout),
            ("rate", self._rate),
        ):
            if isinstance(data.get(key), int):
                widget.setValue(int(data[key]))
        self._rate_enabled.setChecked(bool(data.get("rate_enabled", False)))
        self._rate.setEnabled(self._rate_enabled.isChecked())
        self._skip_tls.setChecked(bool(data.get("skip_tls", True)))
        if isinstance(data.get("status_csv"), str):
            self._status_csv.setText(data["status_csv"])
        if isinstance(data.get("custom_exts"), str):
            self._custom_exts.setText(data["custom_exts"])
        self._wide_net.setChecked(bool(data.get("wide_net", False)))
        groups = data.get("groups", [])
        if isinstance(groups, list):
            for group, box in self._group_boxes.items():
                box.setChecked(group in groups)
        self._loading = False
        self._sync_status_combo()  # restore the preset dropdown to match the loaded CSV
        self._refresh()

    def _on_run(self) -> None:
        settings = self._current_settings()
        if not settings.url or not settings.wordlist:
            # don't fail silently — tell the operator which field the Run button needs
            missing = "a target URL" if not settings.url else "a wordlist"
            QToolTip.showText(
                self._run_btn.mapToGlobal(QPoint(0, self._run_btn.height())),
                f"Set {missing} first.",
                self._run_btn,
            )
            return
        self.run_requested.emit(
            build_command(settings), settings.output_file, settings.tool, self._port
        )

    def _on_fingerprint(self) -> None:
        # Tier-1 web fingerprint: whatweb → structured findings (server, title, versions), the same
        # parse path the dir-bust tools use. --log-brief writes the summary to the parsed output
        # file (whatweb streams to stdout otherwise, which the parser never sees).
        url = self._url.text().strip()
        if not url:
            return
        output_rel = f"http/{self._port}/whatweb.txt"
        command = f"whatweb --colour=never --log-brief={output_rel} {url}"
        self.run_requested.emit(command, output_rel, "whatweb", self._port)

    def _on_dry_run(self) -> None:
        self.dry_run_requested.emit(build_command(self._current_settings()))

    def _on_add_report(self) -> None:
        self.add_report_requested.emit(build_command(self._current_settings()))
