from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QWidget

from oscprecon.gui.task_manager import TaskManager


class TaskStatusBar(QWidget):
    # why: a strip showing every running recon task with its own Cancel (✕) button, so parallel
    # work is visible and individually stoppable under exam pressure (§23 Phase 5).
    def __init__(self, manager: TaskManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._manager = manager
        self._row = QHBoxLayout(self)
        self._row.setContentsMargins(6, 2, 6, 2)
        manager.changed.connect(self.refresh)
        self.refresh()

    def _clear(self) -> None:
        while self._row.count():
            item = self._row.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.deleteLater()

    def refresh(self) -> None:
        self._clear()
        tasks = self._manager.tasks()
        if not tasks:
            self._row.addWidget(QLabel("idle"))
            self._row.addStretch(1)
            return
        self._row.addWidget(QLabel(f"{len(tasks)} running:"))
        for task in tasks:
            self._row.addWidget(QLabel(task.label))
            button = QPushButton("✕")
            button.setToolTip(f"Cancel {task.label}")
            button.setFixedWidth(26)
            button.clicked.connect(lambda _checked=False, worker=task.worker: self._cancel(worker))
            self._row.addWidget(button)
        self._row.addStretch(1)

    def _cancel(self, worker: object) -> None:
        self._manager.cancel(worker)
