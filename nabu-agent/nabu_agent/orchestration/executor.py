"""Run executor — drives one run through the state machine, publishing live node-state events for
the BloodHound-style map and persisting them for replay.

Two modes:
  * ``run_demo``  — a scripted choreography (no tools, no live target) so the live map animates
    end-to-end: the run node goes green, services appear, per-service agents light up green → done,
    findings attach, the writer runs, report ready. This is what makes "agents in motion" reviewable
    without an authorized target on hand.
  * ``run_real``  — the real single-target recon via the engine tools through the chokepoint
    (check_alive → run_scan → enum_service per service → generate_report), emitting the same event
    shapes. Runs the blocking engine in a thread; honours the cancel flag.

Both publish canonical :class:`nabu_agent.events.Event` dicts via a ``publish`` callback (the runs
service persists each to ``run_events`` with its seq, then pushes to Redis for the WebSocket).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from nabu_agent.events.schema import NodeState, RunEventType

# publish(event_type, data, *, node_id, node_state, task_id) -> Awaitable[None]
Publish = Callable[..., Awaitable[None]]

_DEMO_SERVICES = [
    {"port": 22, "proto": "tcp", "service": "ssh", "product": "OpenSSH 8.9"},
    {"port": 80, "proto": "tcp", "service": "http", "product": "nginx 1.18"},
    {"port": 445, "proto": "tcp", "service": "smb", "product": "Samba 4.15"},
]
_DEMO_FINDINGS = [
    {"engine_key": "smb-signing", "value": "SMB signing not required", "port": 445, "category": "exposure"},
    {"engine_key": "http-title", "value": "Apache default page", "port": 80, "category": "info"},
]


async def run_demo(run_id: str, target: str, publish: Publish, *, step_delay: float = 0.6) -> str:
    """Emit a realistic recon choreography so the live map animates. Returns the terminal state."""
    run_node = f"run-{run_id}"
    host_node = f"host-{target}"

    async def emit(t: RunEventType, **data: Any) -> None:
        await publish(t, data)

    await emit(RunEventType.RUN_STATUS, node_id=run_node, node_state=NodeState.ACTIVE,
               state="scanning", label="recon run")
    await emit(RunEventType.LOG_LINE, line=f"[scan] staged nmap against {target}")
    await emit(RunEventType.TASK_CREATED, node_id=host_node, node_state=NodeState.ACTIVE,
               kind="host", label=target)
    await asyncio.sleep(step_delay)

    # discover services (nodes appear, host stays active)
    for s in _DEMO_SERVICES:
        nid = f"svc-{target}-{s['port']}-{s['proto']}"
        await emit(RunEventType.TASK_CREATED, node_id=nid, node_state=NodeState.DONE, kind="service",
                   label=f"{s['port']}/{s['service']}", parent=host_node, **s)
        await emit(RunEventType.LOG_LINE, line=f"[scan] {s['port']}/{s['proto']} open — {s['product']}")
        await asyncio.sleep(step_delay / 2)

    await emit(RunEventType.TASK_UPDATED, node_id=host_node, node_state=NodeState.DONE)

    # per-service enum agents: queued -> active(green) -> done(teal)
    for s in _DEMO_SERVICES:
        svc_node = f"svc-{target}-{s['port']}-{s['proto']}"
        agent_node = f"agent-enum-{s['port']}"
        await emit(RunEventType.TASK_CREATED, node_id=agent_node, node_state=NodeState.QUEUED,
                   kind="agent", role="enum", label=f"enum {s['service']}", parent=svc_node)
    for s in _DEMO_SERVICES:
        agent_node = f"agent-enum-{s['port']}"
        await emit(RunEventType.TASK_UPDATED, node_id=agent_node, node_state=NodeState.ACTIVE)
        await emit(RunEventType.LOG_LINE, line=f"[enum] {s['service']} :{s['port']} — Tier-1 recon")
        await asyncio.sleep(step_delay)
        await emit(RunEventType.TASK_UPDATED, node_id=agent_node, node_state=NodeState.DONE)

    # findings attach
    for f in _DEMO_FINDINGS:
        fid = f"finding-{f['engine_key']}"
        st = NodeState.ERROR if f["category"] == "vulnerable" else NodeState.DONE
        await emit(RunEventType.FINDING_ADDED, node_id=fid, node_state=st, kind="finding",
                   label=f["value"][:40], parent=f"svc-{target}-{f['port']}-tcp", category=f["category"])
        await emit(RunEventType.LOG_LINE, line=f"[finding] {f['value']}")
        await asyncio.sleep(step_delay / 3)

    # writer / report
    report_node = f"report-{run_id}"
    await emit(RunEventType.TASK_CREATED, node_id=report_node, node_state=NodeState.ACTIVE,
               kind="report", label="report", parent=run_node)
    await emit(RunEventType.LOG_LINE, line="[report] synthesizing findings + next steps")
    await asyncio.sleep(step_delay)
    await emit(RunEventType.TASK_UPDATED, node_id=report_node, node_state=NodeState.DONE)
    await emit(RunEventType.RUN_STATUS, node_id=run_node, node_state=NodeState.DONE, state="report_ready")
    return "done"
