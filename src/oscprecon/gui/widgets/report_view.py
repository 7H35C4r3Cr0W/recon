from __future__ import annotations

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QHBoxLayout, QPushButton, QTextBrowser, QVBoxLayout, QWidget

from oscprecon.profile import Profile
from oscprecon.reporter import Reporter


class ReportView(QWidget):
    # why: §23 Phase 5 — a rendered report.md preview. QTextBrowser.setMarkdown renders natively
    # (no web engine, no extra deps); "Open in editor" hands report.md to the OS default app.
    def __init__(self) -> None:
        super().__init__()
        self._profile: Profile | None = None

        self._browser = QTextBrowser()
        self._browser.setOpenExternalLinks(True)

        self._regenerate = QPushButton("Regenerate")
        self._regenerate.clicked.connect(self.reload)
        self._open_editor = QPushButton("Open in editor")
        self._open_editor.clicked.connect(self._on_open_in_editor)

        bar = QHBoxLayout()
        bar.addWidget(self._regenerate)
        bar.addWidget(self._open_editor)
        bar.addStretch(1)

        layout = QVBoxLayout(self)
        layout.addLayout(bar)
        layout.addWidget(self._browser, stretch=1)
        self.reload()

    def set_profile(self, profile: Profile | None) -> None:
        self._profile = profile
        self.reload()

    def reload(self) -> None:
        # why: enabled-but-no-op buttons read as broken — gate both on a loaded profile.
        self._regenerate.setEnabled(self._profile is not None)
        self._open_editor.setEnabled(self._profile is not None)
        if self._profile is None:
            self._browser.setMarkdown("_No profile loaded._")
            return
        # why: render in-memory (no disk write / archive) so merely viewing the tab doesn't spam
        # report-archive/ — "Open in editor" is the explicit path that persists report.md.
        self._browser.setMarkdown(Reporter(self._profile).render())

    def _on_open_in_editor(self) -> None:
        if self._profile is None:
            return
        path = Reporter(self._profile).write()  # persist the current report, then hand it to the OS
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
