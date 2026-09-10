"""THE one canonical run-event envelope, imported by every publisher (worker/tasks) and every
consumer (WebSocket hub, frontend client). Defining it once keeps the live-progress contract from
drifting between the fan-out workers and the browser.

Secrets are NEVER placed in ``data`` — credential material is referenced by ``credential_ref`` only.

Node-state colours drive the BloodHound-style live map (owner requirement): as agents move, the
publisher stamps ``data.node_id`` + ``data.node_state`` and the frontend re-colours that node live.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class RunEventType(StrEnum):
    RUN_STATUS = "run.status"                 # {from, to} state transition (+ node_state on the run node)
    TASK_CREATED = "task.created"             # a node appeared on the map
    TASK_UPDATED = "task.updated"             # node_state change (coalesced ~250ms)
    LOG_LINE = "log.line"                     # one engine on_line line (coalesced) — the live log
    FINDING_ADDED = "finding.added"           # a new finding node (severity-tagged)
    USAGE = "usage"                           # LLM token usage delta
    CHECKPOINT_REQUESTED = "checkpoint.requested"   # agent surfaced a spray/exploit proposal
    CHECKPOINT_DECIDED = "checkpoint.decided"       # a human approved/rejected it
    APPROVAL_REQUIRED = "approval.required"   # run parked in awaiting_approval (node → stuck/yellow)
    HEARTBEAT = "heartbeat"                   # ~20s keepalive, decoupled from scan output
    ERROR = "error"                           # node → error/red
    DONE = "done"


class NodeState(StrEnum):
    """Live colour for a map node. The frontend maps these to colours."""

    QUEUED = "queued"       # grey  — created, not started
    ACTIVE = "active"       # green (glowing) — running / where the run currently is
    STUCK = "stuck"         # yellow — blocked / awaiting approval / missing tool
    ERROR = "error"         # red   — failed / tool error
    DONE = "done"           # teal  — completed successfully


# suggested colours (frontend may override); kept here so backend + frontend agree on meaning
NODE_COLORS: dict[str, str] = {
    NodeState.QUEUED: "#8394a0",
    NodeState.ACTIVE: "#2f9e57",
    NodeState.STUCK: "#b7791f",
    NodeState.ERROR: "#d05050",
    NodeState.DONE: "#2b7fb8",
}


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


CLIENT_OPS = frozenset({"ping", "approve", "reject"})


def make_event(
    type_: RunEventType, run_id: str, seq: int, ts: float, *,
    data: dict[str, Any] | None = None, agent_id: str | None = None, task_id: str | None = None,
) -> Event:
    return Event(type=type_, run_id=run_id, seq=seq, ts=ts, data=data or {},
                 agent_id=agent_id, task_id=task_id)


def node_update(run_id: str, seq: int, ts: float, node_id: str, state: NodeState, *,
                label: str | None = None, task_id: str | None = None,
                extra: dict[str, Any] | None = None) -> Event:
    """Build a task.updated event that re-colours one map node."""
    data: dict[str, Any] = {"node_id": node_id, "node_state": state.value}
    if label is not None:
        data["label"] = label
    if extra:
        data.update(extra)
    return make_event(RunEventType.TASK_UPDATED, run_id, seq, ts, data=data, task_id=task_id or node_id)
