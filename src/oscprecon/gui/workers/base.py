from __future__ import annotations

import threading

from PySide6.QtCore import QThread


class CancellableThread(QThread):
    # why: a shared cancel Event that each worker threads into shell.run (which kills the child)
    # and checks between steps, so the status-bar Cancel button stops in-flight recon promptly.
    def __init__(self) -> None:
        super().__init__()
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()
