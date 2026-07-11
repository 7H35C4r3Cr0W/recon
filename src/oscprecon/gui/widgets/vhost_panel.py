from __future__ import annotations

from typing import Any

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from oscprecon.gui.widgets.wordlist_picker import WordlistPicker
from oscprecon.models import DiscoveredService
from oscprecon.modules.http import is_tls
from oscprecon.modules.vhost import (
    DEFAULT_VHOST_WORDLIST,
    TOOL_LABELS,
    VhostScanSettings,
    build_command,
    default_output,
    wildcard_probe_command,
)
from oscprecon.profile import Profile


class VhostPanel(QWidget):
    run_requested = Signal(str, str, str, str)  # command, output_rel, tool, domain
    dry_run_requested = Signal(str)
    wildcard_detect_requested = Signal(str, str)  # probe command, output_rel
    enumerate_as_http_requested = Signal(str)  # vhost

    def __init__(self) -> None:
        super().__init__()
        self._profile: Profile | None = None
        self._target = ""
        self._wordlist = DEFAULT_VHOST_WORDLIST
        self._output_is_custom = False
        self._loading = False

        self._domain = QLineEdit()
        self._domain.setPlaceholderText("target domain (e.g. example.com)")
        self._tool = QComboBox()
        self._tool.addItems(list(TOOL_LABELS))
        self._scheme = QComboBox()
        self._scheme.addItems(["http", "https"])
        self._wordlist_label = QLabel(self._wordlist)
        self._wordlist_label.setWordWrap(True)
        choose = QPushButton("Choose…")
        choose.clicked.connect(self._choose_wordlist)
        wl_row = QHBoxLayout()
        wl_row.addWidget(self._wordlist_label, stretch=1)
        wl_row.addWidget(choose)
        wl_widget = QWidget()
        wl_widget.setLayout(wl_row)

        self._fs = QLineEdit()
        self._fs.setPlaceholderText("optional -fs / --hh filter size")
        detect = QPushButton("Detect wildcard")
        detect.clicked.connect(self._on_detect_wildcard)
        fs_row = QHBoxLayout()
        fs_row.addWidget(self._fs, stretch=1)
        fs_row.addWidget(detect)
        fs_widget = QWidget()
        fs_widget.setLayout(fs_row)

        self._threads = QSpinBox()
        self._threads.setRange(1, 200)
        self._threads.setValue(40)
        self._dns = QLineEdit()
        self._dns.setPlaceholderText("optional DNS server (gobuster dns / dnsrecon)")
        self._output = QLineEdit()

        form = QFormLayout()
        form.addRow("Domain:", self._domain)
        form.addRow("Tool:", self._tool)
        form.addRow("Scheme:", self._scheme)
        form.addRow("Wordlist:", wl_widget)
        form.addRow("Filter size:", fs_widget)
        form.addRow("Threads:", self._threads)
        form.addRow("DNS server:", self._dns)
        form.addRow("Output file:", self._output)

        self._preview = QPlainTextEdit()
        self._preview.setReadOnly(True)
        self._preview.setMaximumHeight(60)
        run = QPushButton("Run")
        run.clicked.connect(self._on_run)
        dry = QPushButton("Dry-run")
        dry.clicked.connect(self._on_dry_run)
        button_row = QHBoxLayout()
        button_row.addWidget(run)
        button_row.addWidget(dry)
        button_row.addStretch(1)

        self._vhosts = QListWidget()
        enumerate_button = QPushButton("Enumerate selected vhost as new HTTP target")
        enumerate_button.clicked.connect(self._on_enumerate)
        vhost_box = QGroupBox("Discovered vhosts")
        vhost_layout = QVBoxLayout(vhost_box)
        vhost_layout.addWidget(self._vhosts)
        vhost_layout.addWidget(enumerate_button)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(QLabel("Command preview:"))
        layout.addWidget(self._preview)
        layout.addLayout(button_row)
        layout.addWidget(vhost_box, stretch=1)

        self._connect_signals()
        self._refresh()

    def _connect_signals(self) -> None:
        self._domain.textChanged.connect(self._refresh)
        self._tool.currentTextChanged.connect(self._refresh)
        self._scheme.currentTextChanged.connect(self._refresh)
        self._fs.textChanged.connect(self._refresh)
        self._threads.valueChanged.connect(self._refresh)
        self._dns.textChanged.connect(self._refresh)
        self._output.textChanged.connect(self._on_output_changed)

    def set_profile(self, profile: Profile) -> None:
        self._profile = profile
        self._target = profile.target.ip
        self._loading = True
        if profile.target.hostname:
            self._domain.setText(profile.target.hostname)
        self._loading = False
        self._apply_settings(profile.module_settings.get("vhost", {}))

    def configure(self, service: DiscoveredService) -> None:
        self._loading = True
        self._scheme.setCurrentText("https" if is_tls(service.service, service.port) else "http")
        self._loading = False
        self._refresh()

    def set_filter_size(self, size: int) -> None:
        self._fs.setText(str(size))

    def add_vhosts(self, vhosts: list[str]) -> None:
        existing = {self._vhosts.item(i).text() for i in range(self._vhosts.count())}
        for vhost in vhosts:
            if vhost not in existing:
                self._vhosts.addItem(vhost)

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

    def _current_settings(self) -> VhostScanSettings:
        text = self._fs.text().strip()
        return VhostScanSettings(
            tool=TOOL_LABELS[self._tool.currentText()],
            target=self._target,
            domain=self._domain.text().strip(),
            wordlist=self._wordlist,
            scheme=self._scheme.currentText(),
            filter_size=int(text) if text.isdigit() else None,
            threads=self._threads.value(),
            dns_server=self._dns.text().strip(),
            output_file=self._output.text().strip(),
        )

    def _refresh(self) -> None:
        if self._loading:
            return
        tool = TOOL_LABELS[self._tool.currentText()]
        if not self._output_is_custom:
            self._loading = True
            self._output.setText(default_output(tool, self._wordlist))
            self._loading = False
        self._preview.setPlainText(build_command(self._current_settings()))
        self._save_only()

    def _on_output_changed(self) -> None:
        if not self._loading:
            self._output_is_custom = True
        self._save_only()

    def _save_only(self) -> None:
        if self._profile is None or self._loading:
            return
        self._profile.module_settings["vhost"] = {
            "tool": self._tool.currentText(),
            "scheme": self._scheme.currentText(),
            "wordlist": self._wordlist,
            "threads": self._threads.value(),
            "dns_server": self._dns.text(),
            "filter_size": self._fs.text(),
        }

    def _apply_settings(self, data: dict[str, Any]) -> None:
        self._loading = True
        if isinstance(data.get("tool"), str) and data["tool"] in TOOL_LABELS:
            self._tool.setCurrentText(data["tool"])
        if isinstance(data.get("scheme"), str) and data["scheme"] in ("http", "https"):
            self._scheme.setCurrentText(data["scheme"])
        if isinstance(data.get("wordlist"), str) and data["wordlist"]:
            self._wordlist = data["wordlist"]
            self._wordlist_label.setText(self._wordlist)
        if isinstance(data.get("threads"), int):
            self._threads.setValue(int(data["threads"]))
        if isinstance(data.get("dns_server"), str):
            self._dns.setText(data["dns_server"])
        if isinstance(data.get("filter_size"), str):
            self._fs.setText(data["filter_size"])
        self._loading = False
        self._refresh()

    def _on_run(self) -> None:
        settings = self._current_settings()
        if not settings.domain or not settings.wordlist:
            return
        self.run_requested.emit(
            build_command(settings), settings.output_file, settings.tool, settings.domain
        )

    def _on_dry_run(self) -> None:
        self.dry_run_requested.emit(build_command(self._current_settings()))

    def _on_detect_wildcard(self) -> None:
        domain = self._domain.text().strip()
        if not domain or not self._target:
            return
        probe = wildcard_probe_command(self._scheme.currentText(), self._target, domain)
        self.wildcard_detect_requested.emit(probe, "vhost/wildcard-probe.txt")

    def _on_enumerate(self) -> None:
        item = self._vhosts.currentItem()
        if item is not None:
            self.enumerate_as_http_requested.emit(item.text())
