"""THE one canonical run-event envelope, imported by every publisher (worker/tasks) and every
consumer (WebSocket hub, frontend client). Defining it once is what keeps the live-progress
contract from drifting between the fan-out workers and the browser.

Secrets are NEVER placed in ``data`` — credential material is referenced by ``credential_ref`` only
(the real secret is fetched in the worker via ``ReconAuth.from_credential`` at execution time).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class RunEventType(StrEnum):
    RUN_STATUS = "run.status"                 # {from, to} state transition
    TASK_CREATED = "task.created"             # a fan-out agent_task was created
    TASK_UPDATED = "task.updated"             # state/shell_outcome change (coalesced ~250ms)
    LOG_LINE = "log.line"                     # one engine on_line line (coalesced)
    FINDING_ADDED = "finding.added"           # a new finding row (severity-tagged)
    USAGE = "usage"                           # LLM token usage delta
    CHECKPOINT_REQUESTED = "checkpoint.requested"   # agent surfaced a spray/exploit proposal
    CHECKPOINT_DECIDED = "checkpoint.decided"       # a human approved/rejected it
    APPROVAL_REQUIRED = "approval.required"   # run parked in awaiting_approval
    HEARTBEAT = "heartbeat"                   # ~20s keepalive, decoupled from scan output
    ERROR = "error"
    DONE = "done"


@dataclass(frozen=True)
class Event:
    type: RunEventType
    run_id: str
    seq: int                    # per-run monotonic; drives replay-by-seq on reconnect
    ts: float
    data: dict[str, Any] = field(default_factory=dict)
    agent_id: str | None = None
    task_id: str | None = None

    def to_json(self) -> dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        return d


# Client → server ops are intentionally tiny; every real mutation goes through REST.
CLIENT_OPS = frozenset({"ping", "approve", "reject"})


def make_event(
    type_: RunEventType, run_id: str, seq: int, ts: float, *,
    data: dict[str, Any] | None = None, agent_id: str | None = None, task_id: str | None = None,
) -> Event:
    return Event(type=type_, run_id=run_id, seq=seq, ts=ts, data=data or {},
                 agent_id=agent_id, task_id=task_id)
