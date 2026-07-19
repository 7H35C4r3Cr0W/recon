from __future__ import annotations

import shutil

from PySide6.QtCore import QProcess
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from oscprecon import doctor


class DoctorDialog(QDialog):
    """Host-readiness view: which wrapped tools are present, and a one-click installer for the rest.

    The installer only ever runs `apt-get install -y <packages>` where every package is derived from
    an allow-listed tool's curated hint (strict regex, no shell metacharacters) — never a
    user-supplied string. It elevates via pkexec (a graphical auth prompt) when available, else it
    hands you the exact command to run in a terminal. Nothing installs without your confirmation.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Nabu · Doctor — wrapped tool status")
        self.resize(600, 560)
        self._proc: QProcess | None = None

        summary = QLabel("")
        summary.setWordWrap(True)
        self._summary = summary
        self._view = QTextBrowser()

        self._note = QLabel("")
        self._note.setWordWrap(True)

        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        self._log.setPlaceholderText("install output appears here…")
        self._log.setMaximumHeight(150)
        self._log.setVisible(False)

        self._install_btn = QPushButton("⤓  Install missing (apt)")
        self._install_btn.setToolTip("apt-get install the missing allow-listed tools (asks first)")
        self._install_btn.clicked.connect(self._on_install)
        self._copy_btn = QPushButton("Copy apt command")
        self._copy_btn.clicked.connect(self._on_copy)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        action_row = QHBoxLayout()
        action_row.addWidget(self._install_btn)
        action_row.addWidget(self._copy_btn)
        action_row.addStretch(1)
        action_row.addWidget(buttons)

        layout = QVBoxLayout(self)
        layout.addWidget(self._summary)
        layout.addWidget(self._view, stretch=1)
        layout.addWidget(self._note)
        layout.addWidget(self._log)
        layout.addLayout(action_row)

        self._refresh_report()

    def _refresh_report(self) -> None:
        report = doctor.scan()
        needed = doctor.effective_missing(report)
        req_missing = [t for t in needed if not t.optional]
        spray_missing = [t for t in needed if t.optional]  # hydra/medusa — Spray mode only (§2a)
        required_found = len([t for t in report.found if not t.optional])
        required_total = len(report.required)
        self._plan = doctor.install_plan(report)

        self._summary.setText(
            f"<b>{required_found}/{required_total}</b> wrapped tools found on PATH"
            + (" — all essentials present, exam-ready." if not req_missing else ".")
        )
        self._view.setHtml(self._html(req_missing, spray_missing, report.found))

        have_pkgs = bool(self._plan.packages)
        self._install_btn.setEnabled(have_pkgs)
        self._copy_btn.setEnabled(have_pkgs)
        note = (
            "Interchangeable tools count as covered — e.g. <code>nxc</code>/"
            "<code>crackmapexec</code> by <code>netexec</code>. "
        )
        if have_pkgs:
            pkgs = " ".join(self._plan.packages)
            note += (
                f"<b>Install missing</b> runs <code>apt-get install -y {pkgs}</code> "
                "(via pkexec — a password prompt). Only allow-listed tools are installed."
            )
        else:
            note += "Nothing to apt-install."
        if self._plan.manual:
            manual = ", ".join(f"{t} (<code>{h}</code>)" for t, h in self._plan.manual)
            note += f"<br>Install manually (not apt): {manual}"
        self._note.setText(note)

    def _on_copy(self) -> None:
        from PySide6.QtGui import QGuiApplication

        clip = QGuiApplication.clipboard()
        if clip is not None:
            clip.setText(" ".join(self._plan.apt_argv()))

    def _on_install(self) -> None:
        if self._proc is not None or not self._plan.packages:
            return
        pkgs = " ".join(self._plan.packages)
        if (
            QMessageBox.question(
                self,
                "Install missing tools",
                f"Install these with apt?\n\n{pkgs}\n\n"
                "You'll be asked for your password (pkexec). Only allow-listed tools install.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        runner = shutil.which("pkexec")
        if runner is None:  # no graphical sudo — hand off the exact command
            QMessageBox.information(
                self,
                "Run in a terminal",
                "pkexec isn't available. Run this in a terminal:\n\n"
                + " ".join(self._plan.apt_argv()),
            )
            return
        self._log.setVisible(True)
        self._log.clear()
        self._log.appendPlainText(f"$ pkexec apt-get install -y {pkgs}\n")
        self._install_btn.setEnabled(False)
        proc = QProcess(self)
        proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        proc.readyReadStandardOutput.connect(self._on_output)
        proc.finished.connect(self._on_finished)
        self._proc = proc
        proc.start(runner, ["apt-get", "install", "-y", *self._plan.packages])

    def _on_output(self) -> None:
        if self._proc is None:
            return
        raw = bytes(self._proc.readAllStandardOutput().data())
        self._log.appendPlainText(raw.decode("utf-8", "replace").rstrip("\n"))

    def _on_finished(self, code: int, _status: object = None) -> None:
        outcome = "done." if code == 0 else "failed/cancelled."
        self._log.appendPlainText(f"\n[exit {code}] {outcome}")
        self._proc = None
        self._refresh_report()  # re-scan so freshly-installed tools move to Present

    @staticmethod
    def _html(
        req_missing: list[doctor.ToolStatus],
        spray_missing: list[doctor.ToolStatus],
        found: list[doctor.ToolStatus],
    ) -> str:
        parts: list[str] = []
        if req_missing:
            parts.append("<h4>Missing</h4><ul>")
            parts.extend(f"<li><b>{t.name}</b> — <code>{t.hint}</code></li>" for t in req_missing)
            parts.append("</ul>")
        if spray_missing:
            parts.append("<h4>Spray-mode tools (only needed if Spray mode is on)</h4><ul>")
            parts.extend(f"<li><b>{t.name}</b> — <code>{t.hint}</code></li>" for t in spray_missing)
            parts.append("</ul>")
        parts.append("<h4>Present</h4><ul>")
        parts.extend(f"<li>&#10003; {t.name}</li>" for t in found)
        parts.append("</ul>")
        return "".join(parts)
