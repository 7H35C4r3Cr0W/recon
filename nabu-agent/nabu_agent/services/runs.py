"""Run service: persist run_events (seq-ordered) + publish them to Redis for the live WebSocket, and
drive a run's executor in the background. Same event contract for demo and real runs, so the live
BloodHound-style map + log behave identically whether the recon is simulated or real.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

from sqlalchemy import select

from nabu_agent import bus
from nabu_agent.db.models import Run, RunEvent
from nabu_agent.db.session import sessionmaker
from nabu_agent.events.schema import NodeState, RunEventType, make_event
from nabu_agent.orchestration.executor import run_demo


async def replay_events(db, run_id: str, after: int = 0) -> list[dict[str, Any]]:
    rows = (await db.execute(
        select(RunEvent).where(RunEvent.run_id == run_id, RunEvent.seq > after).order_by(RunEvent.seq)
    )).scalars().all()
    return [{"type": r.type, "run_id": r.run_id, "seq": r.seq,
             "ts": r.ts.timestamp() if r.ts else 0.0, "data": r.payload,
             "task_id": r.payload.get("node_id")} for r in rows]


async def _emit(run_id: str, type_: RunEventType, data: dict[str, Any]) -> None:
    """Assign a seq, persist a run_events row, and publish to Redis for live subscribers."""
    seq = await bus.next_seq(run_id)
    ev = make_event(type_, run_id, seq, time.time(), data=data, task_id=data.get("node_id"))
    async with sessionmaker()() as db:
        db.add(RunEvent(run_id=run_id, seq=seq, type=type_.value, task_id=data.get("node_id"),
                        payload=dict(data)))
        await db.commit()
    await bus.publish_event(run_id, ev.to_json())


async def _set_state(run_id: str, state: str) -> None:
    async with sessionmaker()() as db:
        run = (await db.execute(select(Run).where(Run.id == run_id))).scalar_one_or_none()
        if run:
            run.state = state
            await db.commit()




async def execute_run(run_id: str, target: str, kind: str = "demo", *, project_id: str | None = None) -> None:
    """Background driver: run the choreography (demo) or real recon, persisting + streaming events."""
    async def publish(type_: RunEventType, data: dict[str, Any]) -> None:
        await _emit(run_id, type_, data)

    # a threading.Event fed by the Redis cancel flag, handed to the (blocking) engine calls
    cancel_event = threading.Event()

    async def watch_cancel() -> None:
        try:
            while not cancel_event.is_set():
                if await bus.is_cancelled(run_id):
                    cancel_event.set()
                    return
                await asyncio.sleep(1.0)
        except Exception:
            pass

    await _set_state(run_id, "scanning")
    watcher = asyncio.create_task(watch_cancel())
    try:
        if kind == "demo":
            final = await run_demo(run_id, target, publish)
        else:
            final = await _run_real(run_id, target, publish, project_id=project_id or "unknown",
                                    cancel_event=cancel_event)
        await _set_state(run_id, final)
    except Exception as exc:  # never leave a run wedged; surface + persist the error live
        await publish(RunEventType.ERROR, {"message": str(exc)})
        await _set_state(run_id, "failed")
    finally:
        cancel_event.set()
        watcher.cancel()


async def _run_real(run_id: str, target: str, publish, *, project_id: str,
                    cancel_event: threading.Event) -> str:
    """REAL single-target recon via the engine tools, through the shell.run chokepoint.

    Emits the SAME node ids/events as the demo (run/host/svc-*/agent-enum-*/finding-*/report) so the
    live map is identical. The blocking engine calls run in a worker thread; the engine's on_line
    sink is bridged onto the event loop as log.line events. Honours the cancel Event.
    """
    import oscprecon.findings as ef

    from nabu_agent.engine import tools as etools
    from nabu_agent.engine.workspace import workspace_for

    loop = asyncio.get_running_loop()

    def on_line(line: str) -> None:
        # called from the engine worker thread — schedule the async publish on the loop
        asyncio.run_coroutine_threadsafe(publish(RunEventType.LOG_LINE, {"line": line}), loop)

    run_node, host_node = f"run-{run_id}", f"host-{target}"
    await publish(RunEventType.RUN_STATUS, {"node_id": run_node, "node_state": NodeState.ACTIVE.value,
                                            "state": "scanning", "label": "recon run"})
    await publish(RunEventType.TASK_CREATED, {"node_id": host_node, "node_state": NodeState.ACTIVE.value,
                                              "kind": "host", "label": target})

    ws = workspace_for(project_id, target)
    profile = await asyncio.to_thread(ws.open_or_create)

    # liveness (best-effort — a down host still gets a scan attempt)
    try:
        await asyncio.to_thread(etools.check_alive, profile, target, on_line=on_line, cancel=cancel_event)
    except Exception as exc:
        await publish(RunEventType.LOG_LINE, {"line": f"[alive] {exc}"})

    # scan
    await asyncio.to_thread(etools.run_scan, profile, "default", on_line=on_line, cancel=cancel_event)
    await publish(RunEventType.TASK_UPDATED, {"node_id": host_node, "node_state": NodeState.DONE.value})

    services = etools.list_discovered_services(profile)["services"]
    for s in services:
        nid = f"svc-{target}-{s['port']}-{s.get('proto', 'tcp')}"
        await publish(RunEventType.TASK_CREATED, {"node_id": nid, "node_state": NodeState.DONE.value,
                      "kind": "service", "label": f"{s['port']}/{s.get('service') or s.get('proto')}",
                      "parent": host_node, "product": s.get("product", "")})

    # per-service enum agents
    partial = False
    for s in services:
        svc_node = f"svc-{target}-{s['port']}-{s.get('proto', 'tcp')}"
        agent_node = f"agent-enum-{s['port']}"
        service_name = s.get("service") or s.get("proto") or ""
        await publish(RunEventType.TASK_CREATED, {"node_id": agent_node, "node_state": NodeState.ACTIVE.value,
                      "kind": "agent", "role": "enum", "label": f"enum {service_name}", "parent": svc_node})
        try:
            await asyncio.to_thread(etools.enum_service, profile, service_name, "full",
                                    port=int(s["port"]), on_line=on_line, cancel=cancel_event)
            await publish(RunEventType.TASK_UPDATED, {"node_id": agent_node, "node_state": NodeState.DONE.value})
        except Exception as exc:  # a blocked/missing enum marks the node stuck; the run continues (partial)
            partial = True
            await publish(RunEventType.TASK_UPDATED, {"node_id": agent_node, "node_state": NodeState.STUCK.value})
            await publish(RunEventType.LOG_LINE, {"line": f"[enum] {service_name}:{s['port']} — {exc}"})
        if cancel_event.is_set():
            return "cancelled"

    # findings → map
    for i, f in enumerate(await asyncio.to_thread(ef.load_findings, profile.directory)):
        fid = f"finding-{f.get('kind', i)}-{f.get('port', '')}"
        await publish(RunEventType.FINDING_ADDED, {"node_id": fid, "node_state": NodeState.DONE.value,
                      "kind": "finding", "label": str(f.get("value", "finding"))[:40],
                      "parent": f"svc-{target}-{f.get('port', 0)}-tcp"})

    # report
    report_node = f"report-{run_id}"
    await publish(RunEventType.TASK_CREATED, {"node_id": report_node, "node_state": NodeState.ACTIVE.value,
                  "kind": "report", "label": "report", "parent": run_node})
    await asyncio.to_thread(etools.generate_report, profile, persist=True)
    await publish(RunEventType.TASK_UPDATED, {"node_id": report_node, "node_state": NodeState.DONE.value})
    await publish(RunEventType.RUN_STATUS, {"node_id": run_node, "node_state": NodeState.DONE.value,
                  "state": "report_ready"})
    await publish(RunEventType.DONE, {"state": "partial" if partial else "done"})
    return "partial" if partial else "done"


def launch(run_id: str, target: str, kind: str = "demo", *, project_id: str | None = None) -> None:
    """Fire-and-forget the executor as an asyncio task in the api process (MVP). Phase 3 moves this
    onto the Arq worker pool for multi-run scale + fan-out."""
    asyncio.create_task(execute_run(run_id, target, kind, project_id=project_id))
