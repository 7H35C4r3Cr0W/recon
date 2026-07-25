from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from PySide6.QtCore import QObject, Signal

# Concurrency model: LANES, not a single exclusive flag.
#
# The old rule was "an nmap scan blocks everything, and everything blocks an nmap scan". That made
# the common exam move impossible: a full `-p-` sweep running while you also fire `--script vuln` at
# 445 and two feroxbuster runs with different wordlists. But it existed for a reason — the recon
# BATTERY (Orchestrator.run_nmap) owns the profile's fixed-name output files, writes report.md, and
# is the one thing that is meaningless to run twice at once on the same box.
#
# So the exclusivity is narrowed to exactly that: one battery at a time. Ad-hoc nmap scans get their
# own lane with a small cap (an exam box should not field six port scans at once), and everything
# else — service recon, content discovery, vhost, vuln scripts — shares the general pool.
DEFAULT_MAX_CONCURRENCY = 6

BATTERY_LANE = "battery"  # Orchestrator.run_nmap / network sweep — one at a time, per §5 above
NMAP_LANE = "nmap"  # ad-hoc nmap: presets, custom scans, per-service vuln scripts
TOOL_LANE = "tool"  # everything else: feroxbuster/gobuster/ffuf, smb, ftp, ssh, dns, ldap, simple

LANE_CAPS: dict[str, int] = {BATTERY_LANE: 1, NMAP_LANE: 3}


@runtime_checkable
class Cancellable(Protocol):
    def cancel(self) -> None: ...


@dataclass
class Task:
    worker: object
    label: str
    lane: str = TOOL_LANE
    tag: str = ""  # unique per run ("http:80 #2") — labels repeat, tags never do
    paths: list[str] = field(default_factory=list)  # output paths this run claimed


class TaskManager(QObject):
    changed = Signal()

    def __init__(self, max_concurrency: int = DEFAULT_MAX_CONCURRENCY) -> None:
        super().__init__()
        self.max_concurrency = max_concurrency
        self._tasks: list[Task] = []
        self._seq = 0

    @property
    def active_count(self) -> int:
        return len(self._tasks)

    def lane_count(self, lane: str) -> int:
        return sum(1 for task in self._tasks if task.lane == lane)

    def lane_cap(self, lane: str) -> int:
        return min(LANE_CAPS.get(lane, self.max_concurrency), self.max_concurrency)

    def can_start(self, *, lane: str = TOOL_LANE) -> bool:
        if len(self._tasks) >= self.max_concurrency:
            return False
        # the battery is the one thing that must be alone in its lane AND must not start while a
        # second battery is pending; every other lane just respects its own cap.
        return self.lane_count(lane) < self.lane_cap(lane)

    def why_blocked(self, lane: str) -> str:
        # §24 — never refuse silently. Say which bound was hit, with the numbers.
        if len(self._tasks) >= self.max_concurrency:
            return f"at capacity ({len(self._tasks)}/{self.max_concurrency} tasks running)"
        cap = self.lane_cap(lane)
        if lane == BATTERY_LANE:
            return "a full recon is already running — Stop it, or use a per-service scan"
        return f"{self.lane_count(lane)}/{cap} {lane} slots are in use"

    def reserve_tag(self, label: str) -> str:
        # a run's unique tag, minted BEFORE the worker exists. Needed because output-file claims are
        # taken before launch (the claim is what stops a rotation clobbering a live file), and a
        # claim keyed on the plain label would let a second run on the same port claim its own file.
        self._seq += 1
        return f"{label} #{self._seq}"

    def add(self, worker: object, label: str, *, lane: str = TOOL_LANE, tag: str = "") -> Task:
        task = Task(worker, label, lane, tag=tag or self.reserve_tag(label))
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

    def task_for(self, worker: object) -> Task | None:
        return next((task for task in self._tasks if task.worker is worker), None)

    def tag_for(self, worker: object) -> str:
        task = self.task_for(worker)
        return task.tag if task is not None else ""

    def cancel(self, worker: object) -> None:
        if isinstance(worker, Cancellable):
            worker.cancel()

    def cancel_all(self) -> None:
        for task in self._tasks:
            self.cancel(task.worker)

    def cancel_lane(self, lane: str) -> None:
        for task in self._tasks:
            if task.lane == lane:
                self.cancel(task.worker)
