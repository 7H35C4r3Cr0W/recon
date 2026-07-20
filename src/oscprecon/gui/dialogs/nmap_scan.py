from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QCompleter,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from oscprecon.nmap_nse import list_scripts
from oscprecon.nmap_scan import ScanSpec, build_nmap_command, validate_scan_target

# scan-type combo -> ScanSpec.scan_type. Connect (-sT) is the default: it needs no raw sockets, so
# it works unprivileged and through most tunnels (ligolo). SYN (-sS) is faster but needs root; UDP
# (-sU) for UDP services; ping-sweep (-sn) just discovers live hosts in a /24.
_SCAN_TYPES = [
    ("TCP connect (-sT)", "connect"),
    ("SYN / half-open (-sS, root)", "syn"),
    ("UDP (-sU)", "udp"),
    ("Ping sweep — hosts only (-sn)", "ping"),
]
_TIMINGS = ["-T0", "-T1", "-T2", "-T3", "-T4", "-T5"]


class NmapScanDialog(QDialog):
    """Configure an nmap scan with real control over the flags, or edit the raw command directly.

    Target may be a single IP or a whole CIDR (/24) — Nabu runs it (over the user's own ligolo
    tunnel, transparently) and organises the results into the topology. This does NOT gate flags;
    the shell chokepoint remains the exec policy (any nmap flag except --script *brute*).
    """

    def __init__(
        self,
        default_target: str,
        host_ips: list[str],
        entry_ip: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Scan a host / range")
        self.resize(560, 440)
        self._entry_ip = entry_ip
        self._command = ""

        self._target = QLineEdit(default_target)
        self._target.setPlaceholderText("10.10.5.23  or a range  10.10.5.0/24")
        self._scan_type = QComboBox()
        for label, _ in _SCAN_TYPES:
            self._scan_type.addItem(label)
        self._no_ping = QCheckBox("-Pn (host is up — skip discovery / ping)")
        self._timing = QComboBox()
        self._timing.addItems(_TIMINGS)
        self._timing.setCurrentText("-T4")
        self._ports = QLineEdit("--top-ports 1000")
        self._ports.setPlaceholderText("--top-ports 1000  ·  -p-  ·  -p 22,80,445")
        self._version = QCheckBox("-sV (version detection)")
        self._version.setChecked(True)
        self._scripts_default = QCheckBox("-sC (default scripts)")
        self._scripts = QLineEdit()
        self._scripts.setPlaceholderText("NSE — e.g. smb-os-discovery,http-title")
        # searchable NSE picker: type to filter (MatchContains), or open the dropdown; Add appends
        # the chosen script above. Sourced from the host's nmap scripts, brute-filtered (§2).
        scripts = list_scripts()
        self._nse_pick = QComboBox()
        self._nse_pick.setEditable(True)
        self._nse_pick.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self._nse_pick.addItems(scripts)
        self._nse_pick.setCurrentText("")
        self._nse_pick.setPlaceholderText(f"search {len(scripts)} NSE scripts…")
        completer = QCompleter(scripts, self)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        completer.setFilterMode(Qt.MatchFlag.MatchContains)
        completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        self._nse_pick.setCompleter(completer)
        self._nse_add = QPushButton("＋ Add")
        self._nse_add.setToolTip("Append the selected NSE script to the field above")
        self._nse_add.clicked.connect(self._on_add_nse)
        nse_row = QHBoxLayout()
        nse_row.setContentsMargins(0, 0, 0, 0)
        nse_row.addWidget(self._nse_pick, stretch=1)
        nse_row.addWidget(self._nse_add)
        self._nse_row = QWidget()
        self._nse_row.setLayout(nse_row)
        self._only_open = QCheckBox("--open (only show open ports)")
        self._os_detect = QCheckBox("-O (OS detection — needs root)")
        self._extra = QLineEdit()
        self._extra.setPlaceholderText("extra flags — e.g. --min-rate 1500  --open  -6")
        self._pivot = QComboBox()
        self._pivot.addItems(host_ips or [entry_ip])
        self._pivot.setCurrentText(entry_ip)

        form = QFormLayout()
        form.addRow("Target (IP or CIDR):", self._target)
        form.addRow("Scan type:", self._scan_type)
        form.addRow("", self._no_ping)
        form.addRow("Timing:", self._timing)
        form.addRow("Ports:", self._ports)
        form.addRow("", self._version)
        form.addRow("", self._scripts_default)
        form.addRow("NSE scripts:", self._scripts)
        form.addRow("Add NSE script:", self._nse_row)
        form.addRow("", self._only_open)
        form.addRow("", self._os_detect)
        form.addRow("Extra flags:", self._extra)
        form.addRow("Pivoted in via:", self._pivot)

        self._raw = QCheckBox("Edit the command directly (raw nmap)")
        self._raw.toggled.connect(self._on_raw_toggled)
        self._preview = QLineEdit()
        self._preview.setReadOnly(True)
        self._preview.setPlaceholderText("nmap …")
        self._preview.setAccessibleName("nmap command preview")
        self._error = QLabel("")
        self._error.setWordWrap(True)
        self._error.setStyleSheet("color: #e06c75;")

        for widget in (self._target, self._ports, self._scripts, self._extra):
            widget.textChanged.connect(self._rebuild_preview)
        self._scan_type.currentIndexChanged.connect(self._rebuild_preview)
        self._timing.currentIndexChanged.connect(self._rebuild_preview)
        for check in (
            self._no_ping,
            self._version,
            self._scripts_default,
            self._only_open,
            self._os_detect,
        ):
            check.toggled.connect(self._rebuild_preview)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Run scan")
        self._buttons.accepted.connect(self._on_accept)
        self._buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self._raw)
        layout.addWidget(QLabel("Command:"))
        layout.addWidget(self._preview)
        layout.addWidget(self._error)
        layout.addWidget(self._buttons)
        self._rebuild_preview()

    def _spec(self) -> ScanSpec:
        return ScanSpec(
            target=self._target.text().strip(),
            scan_type=_SCAN_TYPES[self._scan_type.currentIndex()][1],
            no_ping=self._no_ping.isChecked(),
            ports=self._ports.text(),
            timing=self._timing.currentText(),
            version=self._version.isChecked(),
            default_scripts=self._scripts_default.isChecked(),
            scripts=self._scripts.text(),
            only_open=self._only_open.isChecked(),
            os_detect=self._os_detect.isChecked(),
            extra=self._extra.text(),
        )

    def _on_add_nse(self) -> None:
        name = self._nse_pick.currentText().strip()
        if not name:
            return
        existing = [s.strip() for s in self._scripts.text().split(",") if s.strip()]
        if name not in existing:
            existing.append(name)
        self._scripts.setText(",".join(existing))  # triggers _rebuild_preview via textChanged
        self._nse_pick.setCurrentText("")

    def _rebuild_preview(self) -> None:
        if self._raw.isChecked():
            return  # the user owns the text in raw mode — never overwrite it
        try:
            self._preview.setText(build_nmap_command(self._spec()))
            self._error.setText("")
        except ValueError as exc:
            self._preview.setText("")
            self._error.setText(str(exc))

    def _on_raw_toggled(self, on: bool) -> None:
        self._preview.setReadOnly(not on)
        for widget in (
            self._scan_type,
            self._no_ping,
            self._timing,
            self._ports,
            self._version,
            self._scripts_default,
            self._scripts,
            self._nse_row,
            self._only_open,
            self._os_detect,
            self._extra,
        ):
            widget.setEnabled(not on)
        if not on:
            self._rebuild_preview()

    def _on_accept(self) -> None:
        try:
            target = validate_scan_target(self._target.text())
        except ValueError as exc:
            self._error.setText(str(exc))
            return
        command = self._preview.text().strip()
        if command.split()[:1] != ["nmap"]:
            self._error.setText("the command must start with 'nmap'.")
            return
        # the target field drives how results are organised (entry / host / range) even in raw mode,
        # where the raw command is what actually runs — so validate the target regardless.
        self._command = command
        self._target.setText(target)
        self.accept()

    def command(self) -> str:
        return self._command

    def target(self) -> str:
        return self._target.text().strip()

    def pivot_source(self) -> str:
        return self._pivot.currentText().strip()
