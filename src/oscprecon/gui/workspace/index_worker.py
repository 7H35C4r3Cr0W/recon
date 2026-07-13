from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal

from oscprecon.gui.workers.base import CancellableThread
from oscprecon.workspace import scan_workspace


class WorkspaceIndexWorker(CancellableThread):
    """Scans the workspace root off the GUI thread so a large workspace never blocks the UI."""

    done = Signal(object)  # list[ProfileSummary]
    failed = Signal(str)

    def __init__(self, root: Path) -> None:
        super().__init__()
        self._root = Path(root)

    def run(self) -> None:
        try:
            summaries = scan_workspace(self._root)
        except Exception as exc:  # boundary: surface a scan failure rather than crash the worker
            self.failed.emit(str(exc))
            return
        if not self._cancel.is_set():
            self.done.emit(summaries)
