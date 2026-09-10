"""Run service: persist run_events (seq-ordered) + publish them to Redis for the live WebSocket, and
drive a run's executor in the background. This is the seam between the API and the orchestration
executor; it keeps event persistence + fan-out identical for demo and real runs.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from sqlalchemy import select

from nabu_agent import bus
from nabu_agent.db.models import Run, RunEvent
from nabu_agent.db.session import sessionmaker
from nabu_agent.events.schema import RunEventType, make_event
from nabu_agent.orchestration.executor import run_demo


async def replay_events(db, run_id: str, after: int = 0) -> list[dict[str, Any]]:
    rows = (await db.execute(
        select(RunEvent).where(RunEvent.run_id == run_id, RunEvent.seq > after).order_by(RunEvent.seq)
    )).scalars().all()
    return [{"type": r.type, "run_id": r.run_id, "seq": r.seq,
             "ts": r.ts.timestamp() if r.ts else 0.0, "data": r.payload,
             "task_id": r.payload.get("task_id")} for r in rows]


async def _emit(run_id: str, type_: RunEventType, data: dict[str, Any]) -> None:
    """Assign a seq, persist a run_events row, and publish to Redis for live subscribers."""
    seq = await bus.next_seq(run_id)
    ev = make_event(type_, run_id, seq, time.time(), data=data, task_id=data.get("node_id"))
    payload = dict(data)
    async with sessionmaker()() as db:
        db.add(RunEvent(run_id=run_id, seq=seq, type=type_.value, task_id=data.get("node_id"),
                        payload=payload))
        await db.commit()
    await bus.publish_event(run_id, ev.to_json())


async def _set_state(run_id: str, state: str) -> None:
    async with sessionmaker()() as db:
        run = (await db.execute(select(Run).where(Run.id == run_id))).scalar_one_or_none()
        if run:
            run.state = state
            await db.commit()


async def execute_run(run_id: str, target: str, kind: str = "demo") -> None:
    """Background driver: run the choreography (or real recon), persisting + streaming each event."""
    async def publish(type_: RunEventType, data: dict[str, Any]) -> None:
        await _emit(run_id, type_, data)

    await _set_state(run_id, "scanning")
    try:
        if kind == "demo":
            final = await run_demo(run_id, target, publish)
        else:
            final = await _run_real(run_id, target, publish)
        await _set_state(run_id, final)
    except Exception as exc:  # never leave a run wedged; surface the error live + persist it
        await publish(RunEventType.ERROR, {"message": str(exc)})
        await _set_state(run_id, "failed")


async def _run_real(run_id: str, target: str, publish) -> str:
    """Real single-target recon via the engine tools (Phase 2.6 fill). Guarded so the demo path is
    always available; wired to engine.tools.check_alive/run_scan/enum_service/generate_report through
    the chokepoint when a live target + tools are present."""
    # Deferred to the real-engine wiring step; demo mode is the default until then.
    raise NotImplementedError("real recon run wired next; use kind='demo' for the live-map slice")


def launch(run_id: str, target: str, kind: str = "demo") -> None:
    """Fire-and-forget the executor as an asyncio task in the api process (MVP). Phase 3 moves this
    onto the Arq worker pool for multi-run scale."""
    asyncio.create_task(execute_run(run_id, target, kind))
