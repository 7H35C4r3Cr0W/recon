from __future__ import annotations

import re
from typing import Any

from PySide6.QtCore import Qt, Signal
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
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSlider,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from oscprecon.gui.widgets.wordlist_picker import WordlistPicker
from oscprecon.models import DiscoveredService
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

_DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/big.txt"
_TOOL_LABELS = {
    "feroxbuster": "feroxbuster",
    "gobuster dir": "gobuster",
    "ffuf": "ffuf",
    "dirsearch": "dirsearch",
}


class HttpPanel(QWidget):
    run_requested = Signal(str, str, str, int)  # command, output_rel, tool, port
    dry_run_requested = Signal(str)
    add_report_requested = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self._profile: Profile | None = None
        self._port = 80
        self._wordlist = _DEFAULT_WORDLIST
        self._auto_output = ""
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

        self._wide_net = QCheckBox("Wide net (default)")
        self._wide_net.setChecked(True)
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
        self._preview.setMaximumHeight(70)
        run = QPushButton("Run")
        run.clicked.connect(self._on_run)
        dry = QPushButton("Dry-run")
        dry.clicked.connect(self._on_dry_run)
        report = QPushButton("Add to report")
        report.clicked.connect(self._on_add_report)
        button_row = QHBoxLayout()
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

        layout = QVBoxLayout(self)
        layout.addWidget(scroll, stretch=1)
        layout.addWidget(QLabel("Command preview:"))
        layout.addWidget(self._preview)
        layout.addLayout(button_row)

        self._connect_signals()
        self._refresh()

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
        self._custom_exts.textChanged.connect(self._refresh)
        self._threads.valueChanged.connect(self._refresh)
        self._depth.valueChanged.connect(self._refresh)
        self._timeout.valueChanged.connect(self._refresh)
        self._rate.valueChanged.connect(self._refresh)
        self._rate_enabled.toggled.connect(self._on_rate_toggled)
        self._skip_tls.toggled.connect(self._refresh)
        self._status_csv.textChanged.connect(self._refresh)
        self._status_preset.currentTextChanged.connect(self._on_status_preset)
        self._output.textChanged.connect(self._save_only)
        self._wide_net.toggled.connect(self._refresh)
        for box in self._group_boxes.values():
            box.toggled.connect(self._refresh)

    def set_profile(self, profile: Profile) -> None:
        self._profile = profile
        self._apply_settings(profile.module_settings.get("http", {}))

    def configure(self, service: DiscoveredService, ref: ServiceRef) -> None:
        self._port = service.port
        tls = is_tls(service.service, service.port)
        host = self._profile.target.ip if self._profile is not None else ""
        if self._profile is not None and self._profile.target.hostname:
            host = self._profile.target.hostname
        self._url.setText(default_url(host, service.port, tls))
        self._auto_output = ""  # force output refresh for the new port
        self._refresh()

    def _on_rate_toggled(self, enabled: bool) -> None:
        self._rate.setEnabled(enabled)
        self._refresh()

    def _on_status_preset(self, name: str) -> None:
        if name in STATUS_PRESETS:
            self._status_csv.setText(",".join(str(c) for c in STATUS_PRESETS[name]))
        self._refresh()

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
        self._auto_output = ""
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
        new_output = default_output(self._port, tool, self._wordlist)
        if self._output.text() in ("", self._auto_output):
            self._loading = True
            self._output.setText(new_output)
            self._loading = False
        self._auto_output = new_output

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
            "output": self._output.text(),
        }

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
        self._wide_net.setChecked(bool(data.get("wide_net", True)))
        groups = data.get("groups", [])
        if isinstance(groups, list):
            for group, box in self._group_boxes.items():
                box.setChecked(group in groups)
        self._loading = False
        self._refresh()

    def _on_run(self) -> None:
        settings = self._current_settings()
        if not settings.url or not settings.wordlist:
            return
        self.run_requested.emit(
            build_command(settings), settings.output_file, settings.tool, self._port
        )

    def _on_dry_run(self) -> None:
        self.dry_run_requested.emit(build_command(self._current_settings()))

    def _on_add_report(self) -> None:
        self.add_report_requested.emit(build_command(self._current_settings()))
