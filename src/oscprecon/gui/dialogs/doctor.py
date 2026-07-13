from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from oscprecon import doctor


class DoctorDialog(QDialog):
    """Read-only host-readiness view: which wrapped tools are present + how to install the rest.

    Installation is intentionally NOT run from the GUI (apt needs a terminal/sudo) — the dialog
    points the user at `oscprecon-cli doctor --install`, which asks before running anything.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Doctor — wrapped tool status")
        self.resize(560, 480)

        report = doctor.scan()
        found = report.found
        # why: real gaps only — a tool covered by a present alternative (e.g. nxc/crackmapexec when
        # netexec is installed) is NOT a gap, so a fully-equipped host correctly reads exam-ready.
        needed = doctor.effective_missing(report)

        summary = QLabel(
            f"<b>{len(found)}/{len(report.tools)}</b> wrapped tools found on PATH"
            + (" — all essentials present, exam-ready." if not needed else ".")
        )
        summary.setWordWrap(True)

        self._view = QTextBrowser()
        self._view.setHtml(self._html(needed, found))

        note = QLabel(
            "Interchangeable tools count as covered — e.g. <code>nxc</code>/"
            "<code>crackmapexec</code> by <code>netexec</code>, and <code>GetX.py</code> by "
            "<code>impacket-GetX.py</code> (and vice-versa). To install what's missing, run "
            "<code>oscprecon-cli doctor --install</code> in a terminal — it prints the exact "
            "apt command and asks before running anything. Only allow-listed tools are installed."
        )
        note.setWordWrap(True)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(summary)
        layout.addWidget(self._view, stretch=1)
        layout.addWidget(note)
        layout.addWidget(buttons)

    @staticmethod
    def _html(needed: list[doctor.ToolStatus], found: list[doctor.ToolStatus]) -> str:
        parts: list[str] = []
        if needed:
            parts.append("<h4>Missing</h4><ul>")
            parts.extend(f"<li><b>{t.name}</b> — <code>{t.hint}</code></li>" for t in needed)
            parts.append("</ul>")
        parts.append("<h4>Present</h4><ul>")
        parts.extend(f"<li>&#10003; {t.name}</li>" for t in found)
        parts.append("</ul>")
        return "".join(parts)
