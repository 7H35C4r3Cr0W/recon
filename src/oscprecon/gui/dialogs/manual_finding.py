from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from oscprecon import finding_severity
from oscprecon.gui.theme import styles
from oscprecon.profile import Profile

# Operator-entered findings (user request). Parsers only see what a tool printed — the working SQLi,
# the credential spotted in a PDF, the path that actually gave a foothold are things YOU found.
# This dialog captures one, with the context that makes it useful later: where it was (host + port),
# how to reproduce it (PoC), and how bad it is. It writes into the same findings.json as parsed
# findings, so it shows up in the Findings view, the graph and report.md.

# category -> what it means for the operator, so the severity picker isn't jargon.
_CATEGORY_HELP: tuple[tuple[str, str], ...] = (
    (finding_severity.INFO, "info — a neutral fact (version, banner, username)"),
    (finding_severity.REFERENCE, "reference — a pointer to read (CVE, exploit, article)"),
    (finding_severity.ACCESS, "access — anonymous / guest / default login worked"),
    (finding_severity.EXPOSURE, "exposure — data reachable without credentials"),
    (finding_severity.RELAY_RISK, "relay-risk — weak posture (signing off, open relay)"),
)

# common kinds, offered as suggestions — the field stays free text.
_KINDS: tuple[str, ...] = (
    "note",
    "vuln",
    "credential",
    "foothold",
    "privesc",
    "misconfig",
    "exposure",
    "endpoint",
    "user",
    "share",
    "hostname",
    "todo",
)


class ManualFindingDialog(QDialog):
    """Add or edit one operator-entered finding."""

    def __init__(
        self,
        parent: QWidget | None = None,
        profile: Profile | None = None,
        finding: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(parent)
        editing = finding is not None
        self.setWindowTitle("Edit Finding" if editing else "Add Finding")
        self.setMinimumWidth(560)
        self._finding = finding or {}

        self._title = QLineEdit()
        self._title.setPlaceholderText("what you found (e.g. 'SQLi in /search.php?q=')")
        self._kind = QComboBox()
        self._kind.setEditable(True)
        self._kind.addItems(_KINDS)
        self._severity = QComboBox()
        for value, label in _CATEGORY_HELP:
            self._severity.addItem(label, value)
        self._host = QComboBox()
        self._host.setEditable(True)
        self._host.setToolTip("Where you found it — the target, a discovered host, or anything you type")
        self._port = QComboBox()
        self._port.setEditable(True)
        self._port.setToolTip("The port it was on (blank if it isn't port-specific)")
        self._module = QLineEdit()
        self._module.setPlaceholderText("manual")
        self._module.setToolTip("Which service/module this belongs under in the report (e.g. http)")
        self._poc = QPlainTextEdit()
        self._poc.setPlaceholderText(
            "How to reproduce it — the request, the payload, the exact command…"
        )
        self._poc.setMinimumHeight(90)
        self._detail = QPlainTextEdit()
        self._detail.setPlaceholderText("Notes — context, what you tried, what to do next")
        self._detail.setMinimumHeight(70)
        self._reference = QLineEdit()
        self._reference.setPlaceholderText("https://… (optional)")

        self._populate_context(profile)
        if editing:
            self._prefill(self._finding)
        elif profile is not None:
            self._host.setCurrentText(profile.target.ip)

        form = QFormLayout()
        form.addRow("Finding:", self._title)
        form.addRow("Kind:", self._kind)
        form.addRow("Severity:", self._severity)
        form.addRow("Host / source IP:", self._host)
        form.addRow("Port:", self._port)
        form.addRow("Module:", self._module)
        form.addRow("PoC / repro:", self._poc)
        form.addRow("Notes:", self._detail)
        form.addRow("Reference:", self._reference)

        self._error = QLabel("")
        self._error.setStyleSheet("color: #d9534f;")
        self._error.setVisible(False)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        if ok is not None:
            ok.setText("Save finding")
            ok.setStyleSheet(styles.accent_button())
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self._error)
        layout.addWidget(buttons)
        self._title.setFocus()

    def _populate_context(self, profile: Profile | None) -> None:
        # offer the target + discovered hosts/ports, so the common case is two clicks, while both
        # fields stay free text for anything the scan never saw.
        self._host.addItem("")
        self._port.addItem("")
        if profile is None:
            return
        hosts: list[str] = []
        for value in (profile.target.ip, profile.target.hostname or ""):
            if value and value not in hosts:
                hosts.append(value)
        for host in profile.discovered_hosts:
            for value in (host.ip, host.hostname):
                if value and value not in hosts:
                    hosts.append(value)
        self._host.addItems(hosts)
        seen: set[int] = set()
        for service in sorted(profile.discovered_services, key=lambda s: s.port):
            if service.port in seen:
                continue
            seen.add(service.port)
            label = f"{service.port} — {service.service}" if service.service else str(service.port)
            self._port.addItem(label, str(service.port))

    def _prefill(self, finding: dict[str, Any]) -> None:
        self._title.setText(str(finding.get("value", "")))
        self._kind.setCurrentText(str(finding.get("kind", "")))
        index = self._severity.findData(str(finding.get("severity", "")))
        self._severity.setCurrentIndex(index if index >= 0 else 0)
        self._host.setCurrentText(str(finding.get("host", "")))
        port = finding.get("port")
        self._port.setCurrentText("" if port in (None, "") else str(port))
        module = str(finding.get("module", ""))
        self._module.setText("" if module == "manual" else module)
        self._poc.setPlainText(str(finding.get("poc", "")))
        self._detail.setPlainText(str(finding.get("detail", "")))
        self._reference.setText(str(finding.get("reference", "")))

    def _selected_port(self) -> str:
        # entries read "8080 — http-proxy"; keep only the number, but honour a hand-typed value.
        text = self._port.currentText().strip()
        if not text:
            return ""
        head = text.split()[0]
        return head if head.isdigit() else text

    def _on_accept(self) -> None:
        if not self._title.text().strip():
            self._error.setText("Give the finding a one-line description before saving.")
            self._error.setVisible(True)
            self._title.setFocus()
            return
        self.accept()

    def finding(self) -> dict[str, Any]:
        port = self._selected_port()
        data: dict[str, Any] = {
            "module": self._module.text().strip() or "manual",
            "kind": self._kind.currentText().strip() or "note",
            "value": self._title.text().strip(),
            "detail": self._detail.toPlainText().strip(),
            "severity": str(self._severity.currentData()),
            "host": self._host.currentText().strip(),
            "poc": self._poc.toPlainText().strip(),
            "reference": self._reference.text().strip(),
        }
        if port:
            data["port"] = int(port) if port.isdigit() else port
        existing_id = str(self._finding.get("id", ""))
        if existing_id:
            data["id"] = existing_id
        return data
