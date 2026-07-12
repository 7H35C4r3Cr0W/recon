from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from PySide6.QtCore import QObject, Signal

# why: cap concurrent recon workers so an exam box isn't hammered by a dozen tools at once.
# Nmap discovery stays exclusive (it mutates the shared Profile from its own thread); everything
# else writes shared state on the main thread via done-handlers, so it parallelises safely.
DEFAULT_MAX_CONCURRENCY = 4


@runtime_checkable
class Cancellable(Protocol):
    def cancel(self) -> None: ...


@dataclass
class Task:
    worker: object
    label: str
    exclusive: bool = False


class TaskManager(QObject):
    changed = Signal()

    def __init__(self, max_concurrency: int = DEFAULT_MAX_CONCURRENCY) -> None:
        super().__init__()
        self.max_concurrency = max_concurrency
        self._tasks: list[Task] = []

    @property
    def active_count(self) -> int:
        return len(self._tasks)

    def _has_exclusive(self) -> bool:
        return any(task.exclusive for task in self._tasks)

    def can_start(self, *, exclusive: bool = False) -> bool:
        if self._has_exclusive():
            return False  # an exclusive task (nmap) blocks everything until it finishes
        if exclusive:
            return not self._tasks  # exclusive needs an all-clear
        return len(self._tasks) < self.max_concurrency

    def add(self, worker: object, label: str, *, exclusive: bool = False) -> Task:
        task = Task(worker, label, exclusive)
        self._tasks.append(task)
        self.changed.emit()
        return task

    def remove(self, worker: object) -> None:
        before = len(self._tasks)
        self._tasks = [task for task in self._tasks if task.worker is not worker]
        if len(self._tasks) != before:
            self.changed.emit()

    def tasks(self) -> list[Task]:
        return list(self._tasks)

    def cancel(self, worker: object) -> None:
        if isinstance(worker, Cancellable):
            worker.cancel()

    def cancel_all(self) -> None:
        for task in self._tasks:
            self.cancel(task.worker)
