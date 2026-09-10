"""Run service: persist run_events (seq-ordered) + publish them to Redis for the live WebSocket, and
drive a run's executor in the background. Same event contract for demo and real runs, so the live
BloodHound-style map + log behave identically whether the recon is simulated or real.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select

from nabu_agent import bus
from nabu_agent.db.models import Run, RunEvent
from nabu_agent.db.session import sessionmaker
from nabu_agent.events.schema import NodeState, RunEventType, make_event
from nabu_agent.orchestration.executor import run_demo

_log = structlog.get_logger("nabu_agent.runs")

# Strong refs to in-flight driver tasks so the event loop can't GC/cancel a run mid-execution
# (a bare create_task is only weakly referenced — caught in review).
_RUNNING: set[asyncio.Task] = set()
# Per-run lock so seq-assign + persist + publish happen atomically and in seq order (the WS live
# tail dedups by strictly-increasing seq, so out-of-order publishes would drop events).
_EMIT_LOCKS: dict[str, asyncio.Lock] = {}


async def replay_events(db, run_id: str, after: int = 0) -> list[dict[str, Any]]:
    rows = (await db.execute(
        select(RunEvent).where(RunEvent.run_id == run_id, RunEvent.seq > after).order_by(RunEvent.seq)
    )).scalars().all()
    return [{"type": r.type, "run_id": r.run_id, "seq": r.seq,
             "ts": r.ts.timestamp() if r.ts else 0.0, "data": r.payload,
             "task_id": r.payload.get("node_id")} for r in rows]


async def _emit(run_id: str, type_: RunEventType, data: dict[str, Any]) -> None:
    """Assign a seq, persist a run_events row, and publish to Redis — atomically per run so publish
    order matches seq order (the WS tail dedups by strictly-increasing seq)."""
    lock = _EMIT_LOCKS.setdefault(run_id, asyncio.Lock())
    async with lock:
        seq = await bus.next_seq(run_id)
        ev = make_event(type_, run_id, seq, time.time(), data=data, task_id=data.get("node_id"))
        async with sessionmaker()() as db:
            db.add(RunEvent(run_id=run_id, seq=seq, type=type_.value, task_id=data.get("node_id"),
                            payload=dict(data)))
            await db.commit()
        await bus.publish_event(run_id, ev.to_json())


async def _touch_heartbeat(run_id: str) -> None:
    """Stamp the run's heartbeat so the reaper knows the worker is alive. Best-effort."""
    from sqlalchemy import update
    with contextlib.suppress(Exception):
        async with sessionmaker()() as db:
            await db.execute(update(Run).where(Run.id == run_id).values(heartbeat_at=datetime.now(UTC)))
            await db.commit()


async def _heartbeat_loop(run_id: str, cancel_event: threading.Event, period_s: float = 10.0) -> None:
    """Beat every ~10s while the run executes; stops when the run ends (cancel_event set)."""
    try:
        while not cancel_event.is_set():
            await _touch_heartbeat(run_id)
            await asyncio.sleep(period_s)
    except asyncio.CancelledError:
        pass
    except Exception:  # never let a heartbeat failure affect the run
        _log.warning("heartbeat-loop-error", run_id=run_id, exc_info=True)


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
    await _touch_heartbeat(run_id)
    watcher = asyncio.create_task(watch_cancel())
    heart = asyncio.create_task(_heartbeat_loop(run_id, cancel_event))
    final = "failed"
    try:
        try:
            if kind == "demo":
                final = await run_demo(run_id, target, publish)
            elif kind == "agent":
                final = await _run_agent(run_id, target, publish, project_id=project_id or "unknown",
                                         cancel_event=cancel_event)
            else:
                final = await _run_real(run_id, target, publish, project_id=project_id or "unknown",
                                        cancel_event=cancel_event)
        except asyncio.CancelledError:
            final = "cancelled"
            _log.warning("run-cancelled", run_id=run_id, kind=kind)
            raise
        except Exception as exc:  # surface + persist the error live; never leave a run wedged
            _log.error("run-error", run_id=run_id, kind=kind, target=target, error=str(exc), exc_info=True)
            with contextlib.suppress(Exception):
                await publish(RunEventType.ERROR, {"message": str(exc)})
            final = "failed"
    finally:
        # exactly ONE terminal event on EVERY path (success/error/cancel/no-LLM) so the live WS
        # tail always unblocks; best-effort so a hard cancel can't mask the state write.
        with contextlib.suppress(Exception):
            await _set_state(run_id, final)
        with contextlib.suppress(Exception):
            await _emit(run_id, RunEventType.DONE, {"state": final})
        cancel_event.set()
        watcher.cancel()
        heart.cancel()
        _EMIT_LOCKS.pop(run_id, None)

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

    # per-service enum agents — FAN OUT: one agent per service, concurrent (bounded), so several
    # nodes are 'active' (green) on the live map at once, then join. Blocking engine calls run in
    # worker threads; the per-run _emit lock keeps the event stream ordered.
    from nabu_agent.orchestration.limits import RunLimits

    limits = RunLimits()  # conservative defaults; not driven by the number of services
    services = services[: limits.max_total_tasks]  # hard cap the fan-out width
    sem = asyncio.Semaphore(max(1, limits.max_concurrent_service_agents))
    partial_flags: list[bool] = []

    async def _enum_one(s: dict) -> None:
        svc_node = f"svc-{target}-{s['port']}-{s.get('proto', 'tcp')}"
        agent_node = f"agent-enum-{s['port']}"
        service_name = s.get("service") or s.get("proto") or ""
        async with sem:
            if cancel_event.is_set():
                await publish(RunEventType.TASK_UPDATED, {"node_id": agent_node, "node_state": NodeState.STUCK.value})
                return
            await publish(RunEventType.TASK_CREATED, {"node_id": agent_node, "node_state": NodeState.ACTIVE.value,
                          "kind": "agent", "role": "enum", "label": f"enum {service_name}", "parent": svc_node})
            try:
                await asyncio.to_thread(etools.enum_service, profile, service_name, "full",
                                        port=int(s["port"]), on_line=on_line, cancel=cancel_event)
                await publish(RunEventType.TASK_UPDATED, {"node_id": agent_node, "node_state": NodeState.DONE.value})
            except Exception as exc:  # a blocked/missing enum marks the node stuck; the run continues (partial)
                partial_flags.append(True)
                await publish(RunEventType.TASK_UPDATED, {"node_id": agent_node, "node_state": NodeState.STUCK.value})
                await publish(RunEventType.LOG_LINE, {"line": f"[enum] {service_name}:{s['port']} — {exc}"})

    await asyncio.gather(*[_enum_one(s) for s in services], return_exceptions=True)
    partial = bool(partial_flags)
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
    return "partial" if partial else "done"


async def start(run_id: str, target: str, kind: str = "demo", *, project_id: str | None = None) -> None:
    """Start a run. In production (settings.use_arq) the API just ENQUEUES the supervisor job onto the
    Arq worker pool and returns immediately; in dev/tests it runs in-process. Either way the run
    driver (execute_run) fans out per-service agents concurrently and streams the same events."""
    from nabu_agent.settings import get_settings

    if get_settings().use_arq:
        from nabu_agent import bus

        await bus.enqueue_run(run_id, target, kind, project_id or "unknown")
        return
    launch(run_id, target, kind, project_id=project_id)


def launch(run_id: str, target: str, kind: str = "demo", *, project_id: str | None = None) -> None:
    """Run the driver in-process (dev/tests, or when Arq is disabled). A strong reference is retained
    so the event loop can't GC/cancel the task mid-run."""
    task = asyncio.create_task(execute_run(run_id, target, kind, project_id=project_id))
    _RUNNING.add(task)
    task.add_done_callback(_RUNNING.discard)


async def _run_agent(run_id: str, target: str, publish, *, project_id: str,
                     cancel_event: threading.Event) -> str:
    """LLM-DRIVEN recon with the FULL agent roster: scan → planner → per-service enum agents
    (concurrent) → per-service research agents (concurrent) → reporter. Each LLM agent is an
    AgentRunner (role prompt + allow-listed tools + SafetyGate + budget) and shows as its own node on
    the live map. Requires NABU_LLM_BASE_URL; otherwise fails cleanly. Attack actions are never an
    agent — only a human-gated checkpoint."""
    from nabu_agent.agents.context import ContextAssembler
    from nabu_agent.agents.runner import AgentRunner
    from nabu_agent.engine import tools as etools
    from nabu_agent.engine.workspace import workspace_for
    from nabu_agent.llm.factory import build_provider
    from nabu_agent.orchestration.limits import RunLimits
    from nabu_agent.settings import get_settings

    run_node = f"run-{run_id}"
    host_node = f"host-{target}"
    await publish(RunEventType.RUN_STATUS, {"node_id": run_node, "node_state": NodeState.ACTIVE.value,
                  "state": "scanning", "label": "recon run"})

    settings = get_settings()
    if not settings.llm.base_url:
        await publish(RunEventType.ERROR, {"message": "no LLM configured — set NABU_LLM_BASE_URL to "
                      "your internal OpenAI-compatible endpoint (kind='demo' needs no brain)."})
        return "failed"

    loop = asyncio.get_running_loop()

    def on_line(line: str) -> None:
        asyncio.run_coroutine_threadsafe(publish(RunEventType.LOG_LINE, {"line": line}), loop)

    async def emit(kind_: str, data: dict) -> None:
        await publish(RunEventType.LOG_LINE, data if kind_ == "log.line" else {"line": str(data)})

    provider = build_provider(settings.llm)
    limits = RunLimits()
    partial = False

    async def run_role(role: str, node_id: str, label: str, parent: str, context: dict,
                       edges: list | None = None) -> dict | None:
        """Run one LLM agent role with its own live map node (active → done / error)."""
        if cancel_event.is_set():
            return None
        await publish(RunEventType.TASK_CREATED, {"node_id": node_id, "node_state": NodeState.ACTIVE.value,
                      "kind": "agent", "role": role, "label": label, "parent": parent, "edges": edges or []})
        runner = AgentRunner(role, provider, project_id=project_id, target=target, run_id=run_id,
                             emit=emit, cancel=cancel_event)
        try:
            res = await runner.run(context)
            await publish(RunEventType.TASK_UPDATED, {"node_id": node_id, "node_state": NodeState.DONE.value})
            content = (res or {}).get("content", "")
            if content:
                await publish(RunEventType.LOG_LINE, {"line": f"[{role}] {content[:200]}"})
            return res
        except Exception as exc:
            await publish(RunEventType.TASK_UPDATED, {"node_id": node_id, "node_state": NodeState.ERROR.value})
            await publish(RunEventType.LOG_LINE, {"line": f"[{role}] error: {exc}"})
            return None

    # --- scan (deterministic; real nmap on the internal network) ---
    await publish(RunEventType.TASK_CREATED, {"node_id": host_node, "node_state": NodeState.ACTIVE.value,
                  "kind": "host", "label": target})
    profile = await asyncio.to_thread(workspace_for(project_id, target).open_or_create)
    await asyncio.to_thread(etools.run_scan, profile, "default", on_line=on_line, cancel=cancel_event)
    await publish(RunEventType.TASK_UPDATED, {"node_id": host_node, "node_state": NodeState.DONE.value})
    services = etools.list_discovered_services(profile)["services"][: limits.max_total_tasks]
    for s in services:
        nid = f"svc-{target}-{s['port']}-{s.get('proto', 'tcp')}"
        await publish(RunEventType.TASK_CREATED, {"node_id": nid, "node_state": NodeState.DONE.value,
                      "kind": "service", "label": f"{s['port']}/{s.get('service') or s.get('proto')}",
                      "parent": host_node})
    svc_by_port = {int(s["port"]): f"svc-{target}-{s['port']}-{s.get('proto', 'tcp')}" for s in services}
    planner_node = f"agent-planner-{run_id}"

    # --- planner ---
    base_ctx = await ContextAssembler(project_id, target).build()
    if await run_role("planner", planner_node, "planner", run_node, base_ctx) is None:
        partial = True

    sem = asyncio.Semaphore(max(1, limits.max_concurrent_service_agents))

    def _svc_node(s: dict) -> str:
        return f"svc-{target}-{s['port']}-{s.get('proto', 'tcp')}"

    def _svc_ctx(s: dict) -> dict:
        return {**base_ctx, "host": target, "port": s["port"],
                "service": {"port": s["port"], "service": s.get("service", ""),
                            "product": s.get("product", "")}}

    # --- enum agents (one per service, concurrent) ---
    async def _enum(s: dict) -> dict | None:
        async with sem:
            return await run_role("enum_writer", f"agent-enum-{s['port']}",
                                  f"enum {s.get('service') or s['port']}", _svc_node(s), _svc_ctx(s),
                                  edges=[{"source": planner_node, "target": f"agent-enum-{s['port']}",
                                          "label": "dispatch"}])
    enum_res = await asyncio.gather(*[_enum(s) for s in services], return_exceptions=True)
    if any(r is None or isinstance(r, Exception) for r in enum_res):
        partial = True
    if cancel_event.is_set():
        return "cancelled"

    # --- surface findings the enum agents produced onto the map (edge from the producing agent) ---
    from nabu_agent.engine import gateway as _gw
    with contextlib.suppress(Exception):
        for i, f in enumerate(await asyncio.to_thread(_gw.list_findings, project_id, target, None)):
            port = int(f.get("port") or 0)
            fid = f"finding-{port}-{i}"
            await publish(RunEventType.FINDING_ADDED, {
                "node_id": fid, "node_state": NodeState.DONE.value, "kind": "finding",
                "label": str(f.get("value", "finding"))[:40],
                "parent": svc_by_port.get(port, host_node),
                "edges": [{"source": f"agent-enum-{port}", "target": fid, "label": "found"}]})

    # --- research agents (one per service, concurrent; proposals only) ---
    research_ctx = await ContextAssembler(project_id, target).build()

    async def _research(s: dict) -> dict | None:
        ctx = {**research_ctx, "host": target, "port": s["port"],
               "finding": {"service": s.get("service", ""), "port": s["port"],
                           "product": s.get("product", "")}}
        async with sem:
            return await run_role("research", f"agent-research-{s['port']}",
                                  f"research {s.get('service') or s['port']}", _svc_node(s), ctx,
                                  edges=[{"source": f"agent-enum-{s['port']}",
                                          "target": f"agent-research-{s['port']}", "label": "feeds"}])
    await asyncio.gather(*[_research(s) for s in services], return_exceptions=True)
    if cancel_event.is_set():
        return "cancelled"

    # --- reporter (all agents converge -> report) ---
    report_node = f"agent-report-{run_id}"
    report_edges = [{"source": planner_node, "target": report_node, "label": "feeds"}]
    for s in services:
        report_edges.append({"source": f"agent-enum-{s['port']}", "target": report_node, "label": "feeds"})
        report_edges.append({"source": f"agent-research-{s['port']}", "target": report_node, "label": "feeds"})
    report_ctx = await ContextAssembler(project_id, target).build()
    await run_role("reporter", report_node, "report writer", run_node, report_ctx, edges=report_edges)
    with contextlib.suppress(Exception):
        await asyncio.to_thread(etools.generate_report, profile, persist=True)

    await publish(RunEventType.RUN_STATUS, {"node_id": run_node, "node_state": NodeState.DONE.value,
                  "state": "report_ready"})
    return "partial" if partial else "done"
