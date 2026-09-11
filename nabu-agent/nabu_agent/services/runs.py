"""Run service: persist run_events (seq-ordered) + publish them to Redis for the live WebSocket, and
drive a run's executor in the background. Same event contract for demo and real runs, so the live
BloodHound-style map + log behave identically whether the recon is simulated or real.
"""

from __future__ import annotations

import asyncio
import collections
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


class LogPump:
    """Backpressure for high-volume engine log lines.

    The blocking engine calls ``on_line(line)`` from a worker thread for EVERY line of tool output; a
    chatty scan could otherwise schedule thousands of per-line coroutines (each a DB write + Redis
    publish) and flood the loop. Instead ``feed`` appends to a BOUNDED in-memory deque (O(1), drops
    the oldest when full and counts the overflow), and one async ``drain`` task flushes batches every
    ~250ms as a single ``log.line`` event carrying ``lines: [...]`` (+ ``suppressed`` count). This
    bounds both memory and the publish rate regardless of how fast the engine emits.
    """

    def __init__(self, run_id: str, publish, *, cap: int = 2000, batch: int = 200,
                 interval: float = 0.25) -> None:
        self.run_id = run_id
        self._publish = publish
        self.cap = cap
        self.batch = batch
        self.interval = interval
        self._buf: collections.deque[str] = collections.deque(maxlen=cap)
        self._lock = threading.Lock()
        self._dropped = 0
        self._stop = False

    def feed(self, line: str) -> None:
        """Called from the engine worker thread — thread-safe, non-blocking, bounded."""
        with self._lock:
            if len(self._buf) >= self.cap:
                self._dropped += 1  # deque(maxlen) evicts the oldest line
            self._buf.append(line)

    def _take(self) -> tuple[list[str], int]:
        with self._lock:
            lines = list(self._buf)
            self._buf.clear()
            dropped, self._dropped = self._dropped, 0
        return lines, dropped

    async def _flush(self) -> None:
        lines, dropped = self._take()
        if not lines and not dropped:
            return
        for i in range(0, len(lines) or 1, self.batch):
            chunk = lines[i:i + self.batch]
            data: dict[str, Any] = {"lines": chunk}
            if dropped and i == 0:
                data["suppressed"] = dropped
            with contextlib.suppress(Exception):
                await self._publish(RunEventType.LOG_LINE, data)

    async def drain(self) -> None:
        try:
            while not self._stop:
                await asyncio.sleep(self.interval)
                await self._flush()
        except asyncio.CancelledError:
            pass
        finally:
            await self._flush()  # final flush of anything buffered at shutdown

    async def flush(self) -> None:
        await self._flush()

    def stop(self) -> None:
        self._stop = True

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
    if run_id not in _EMIT_LOCKS:
        _EMIT_LOCKS[run_id] = asyncio.Lock()
    async with _EMIT_LOCKS[run_id]:
        seq = await bus.next_seq(run_id)
        ev = make_event(type_, run_id, seq, time.time(), data=data, task_id=data.get("node_id"))
        async with sessionmaker()() as db:
            db.add(RunEvent(run_id=run_id, seq=seq, type=type_.value, task_id=data.get("node_id"),
                            payload=dict(data)))
            await db.commit()
        await bus.publish_event(run_id, ev.to_json())


async def emit_event(run_id: str, type_: RunEventType, data: dict[str, Any]) -> None:
    """Public wrapper so routers can append one seq-ordered event to a run's live stream (e.g. an
    attack proposal's approval banner + map node)."""
    await _emit(run_id, type_, data)


async def _touch_heartbeat(run_id: str) -> None:
    """Stamp the run's heartbeat so the reaper knows the worker is alive. Best-effort."""
    from sqlalchemy import update
    with contextlib.suppress(Exception):
        async with sessionmaker()() as db:
            await db.execute(update(Run).where(Run.id == run_id).values(heartbeat_at=datetime.now(UTC)))
            await db.commit()


async def _heartbeat_loop(run_id: str, ending: threading.Event, period_s: float = 10.0) -> None:
    """Beat every ~10s until the run actually ENDS (the driver's finally sets `ending`). Deliberately
    NOT tied to the cancel signal: a cancel can take a while to unwind (in-flight engine calls, an
    awaited host job), and the beat must continue through it so the reaper never declares a still-live
    run dead — which would emit a SECOND terminal event and race the run's own final state."""
    try:
        while not ending.is_set():
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




# --- host-count approval gate -------------------------------------------------------------------
# A fan-out to more than RunLimits.approval_required_above_hosts live hosts PARKS the run in
# awaiting_approval and waits for an explicit human decision before spending the fan-out. A paused
# run holds its worker coroutine (heartbeat keeps beating so the reaper leaves it alone), so the wait
# is bounded by _APPROVAL_TIMEOUT_S. Tests monkeypatch these to run fast.
_APPROVAL_POLL_S = 2.0
_APPROVAL_TIMEOUT_S = 30 * 60.0


async def _create_host_checkpoint(run_id: str, target: str, n_hosts: int) -> str:
    from nabu_agent.db.models import Checkpoint
    async with sessionmaker()() as db:
        cp = Checkpoint(run_id=run_id, kind="hosts", status="proposed", target=target,
                        action_id=f"fan-out:{n_hosts}",
                        rationale=f"{n_hosts} live hosts exceed the approval threshold")
        db.add(cp)
        await db.commit()
        return cp.id


async def _checkpoint_status(cp_id: str) -> str:
    from nabu_agent.db.models import Checkpoint
    async with sessionmaker()() as db:
        cp = (await db.execute(select(Checkpoint).where(Checkpoint.id == cp_id))).scalar_one_or_none()
        return cp.status if cp else "rejected"  # a vanished checkpoint -> stop, never silently fan out


async def _expire_checkpoint(cp_id: str) -> None:
    from nabu_agent.db.models import Checkpoint
    async with sessionmaker()() as db:
        cp = (await db.execute(select(Checkpoint).where(Checkpoint.id == cp_id))).scalar_one_or_none()
        if cp and cp.status == "proposed":
            cp.status = "expired"
            await db.commit()


async def _gate_host_fanout(run_id: str, target: str, hosts: list[str], publish, *,
                            project_id: str, cancel_event) -> str | None:
    """Human gate before a large fan-out. Returns None to proceed (approved, or the count is under
    the threshold), or a terminal state string ('cancelled'/'failed') if the run must stop."""
    from nabu_agent.orchestration.limits import RunLimits

    limit = RunLimits().approval_required_above_hosts
    if len(hosts) <= limit:
        return None

    run_node = f"run-{run_id}"
    cp_id = await _create_host_checkpoint(run_id, target, len(hosts))
    await _set_state(run_id, "awaiting_approval")
    await publish(RunEventType.APPROVAL_REQUIRED, {
        "node_id": run_node, "node_state": NodeState.STUCK.value, "state": "awaiting_approval",
        "checkpoint_id": cp_id, "hosts": len(hosts), "threshold": limit,
        "message": f"{len(hosts)} live hosts exceed the approval threshold ({limit}); "
                   "approve to fan out or reject to stop."})
    await publish(RunEventType.LOG_LINE, {"line":
        f"[approval] {len(hosts)} hosts > threshold {limit} — awaiting operator decision (checkpoint {cp_id})"})

    waited = 0.0
    while waited < _APPROVAL_TIMEOUT_S:
        if cancel_event.is_set():
            await publish(RunEventType.LOG_LINE, {"line": "[approval] cancelled while awaiting approval"})
            return "cancelled"
        status = await _checkpoint_status(cp_id)
        if status == "approved":
            await _set_state(run_id, "scanning")
            await publish(RunEventType.RUN_STATUS, {"node_id": run_node,
                          "node_state": NodeState.ACTIVE.value, "state": "scanning"})
            await publish(RunEventType.LOG_LINE,
                          {"line": f"[approval] approved — fanning out to {len(hosts)} host(s)"})
            return None
        if status in ("rejected", "expired"):
            await publish(RunEventType.LOG_LINE,
                          {"line": "[approval] rejected by operator — run stopped before fan-out"})
            return "cancelled"
        await asyncio.sleep(_APPROVAL_POLL_S)
        waited += _APPROVAL_POLL_S

    with contextlib.suppress(Exception):
        await _expire_checkpoint(cp_id)
    await publish(RunEventType.LOG_LINE,
                  {"line": f"[approval] no decision within {_APPROVAL_TIMEOUT_S:.0f}s — run stopped"})
    return "failed"


# --- distributed fan-out (two-pool supervisor) --------------------------------------------------
# In-process (dev/tests, NABU_USE_ARQ off) each host is recon'd in the supervisor coroutine under a
# semaphore. In production (use_arq) the supervisor instead ENQUEUES one recon_host_job per host onto
# the Arq worker pool and AWAITS its result — so the heavy per-host recon spreads across the pool
# (bounded by the worker max_jobs) while the supervisor stays a light coordinator that still owns the
# single terminal DONE. Each host writes its OWN per-host Profile, so separate worker processes never
# race one findings.json (the supervisor need not be the sole Profile writer).
async def _dispatch_host(run_id: str, host: str, kind: str, publish, *, project_id: str,
                         cancel_event, on_line, run_node: str, limits, service_budget: int,
                         provider=None) -> str:
    from nabu_agent.settings import get_settings

    if get_settings().use_arq:
        pool = await bus.get_arq_pool()
        job = await pool.enqueue_job("recon_host_job", run_id, host, kind, project_id, service_budget,
                                     _job_id=f"run:{run_id}:host:{host}")
        return await job.result(timeout=limits.host_job_timeout_s)

    if kind == "agent":
        return await _agent_host(run_id, host, publish, project_id=project_id, cancel_event=cancel_event,
                                 on_line=on_line, run_node=run_node, provider=provider, limits=limits,
                                 service_budget=service_budget)
    return await _recon_host(run_id, host, publish, project_id=project_id, cancel_event=cancel_event,
                             on_line=on_line, run_node=run_node, limits=limits, service_budget=service_budget)


def _make_cancel_watcher(run_id: str, cancel_event: threading.Event):
    """Return a coroutine that flips ``cancel_event`` once the run's Redis cancel flag is set
    (polled ~1s). Shared by the supervisor and each per-host worker job."""
    async def _watch() -> None:
        try:
            while not cancel_event.is_set():
                if await bus.is_cancelled(run_id):
                    cancel_event.set()
                    return
                await asyncio.sleep(1.0)
        except Exception:  # a Redis blip must not crash the run; log so a persistent outage is visible
            _log.debug("cancel-watch-error", run_id=run_id, exc_info=True)
    return _watch


async def run_host_in_worker(run_id: str, host: str, kind: str, project_id: str,
                             service_budget: int) -> str:
    """Body of the ``recon_host_job`` Arq task: recon ONE host as its own worker job. Rebuilds the
    per-run publish/cancel/log machinery, beats the heartbeat (so the reaper leaves the run alone
    while its host jobs run on the pool), and returns the host's terminal string to the supervisor."""
    from nabu_agent.llm.factory import build_provider
    from nabu_agent.orchestration.limits import RunLimits
    from nabu_agent.settings import get_settings

    async def publish(type_: RunEventType, data: dict[str, Any]) -> None:
        await _emit(run_id, type_, data)

    cancel_event = threading.Event()

    watcher = asyncio.create_task(_make_cancel_watcher(run_id, cancel_event)())
    pump = LogPump(run_id, publish)
    pump_task = asyncio.create_task(pump.drain())
    await _touch_heartbeat(run_id)
    run_node, limits = f"run-{run_id}", RunLimits()
    try:
        if kind == "agent":
            provider = build_provider(get_settings().llm)
            return await _agent_host(run_id, host, publish, project_id=project_id, cancel_event=cancel_event,
                                     on_line=pump.feed, run_node=run_node, provider=provider, limits=limits,
                                     service_budget=service_budget)
        return await _recon_host(run_id, host, publish, project_id=project_id, cancel_event=cancel_event,
                                 on_line=pump.feed, run_node=run_node, limits=limits, service_budget=service_budget)
    finally:
        cancel_event.set()
        watcher.cancel()
        pump.stop()
        with contextlib.suppress(Exception):
            await pump.flush()
        pump_task.cancel()


async def execute_run(run_id: str, target: str, kind: str = "demo", *, project_id: str | None = None) -> None:
    """Background driver: run the choreography (demo) or real recon, persisting + streaming events."""
    async def publish(type_: RunEventType, data: dict[str, Any]) -> None:
        await _emit(run_id, type_, data)

    # a threading.Event fed by the Redis cancel flag, handed to the (blocking) engine calls
    cancel_event = threading.Event()
    # a SEPARATE signal set only in the finally — keeps the heartbeat beating through cancel unwind
    ending = threading.Event()

    await _set_state(run_id, "scanning")
    await _touch_heartbeat(run_id)
    # admission: one active run per project (Redis mutex + global ceiling); project-less demo runs
    # skip it. A refused run ends immediately with a clear error rather than racing another's Profile.
    _admitted, _profile_dir = False, ""
    if project_id:
        from nabu_agent.engine.workspace import project_root
        from nabu_agent.orchestration import admission
        _profile_dir = str(project_root(project_id))
        _admitted = await admission.acquire_run_slot(project_id, _profile_dir)
        if not _admitted:
            with contextlib.suppress(Exception):
                await _set_state(run_id, "failed")
            with contextlib.suppress(Exception):
                await _emit(run_id, RunEventType.ERROR, {"message": "run not admitted — another run "
                            "is already active for this project, or the global run limit is reached"})
            with contextlib.suppress(Exception):
                await _emit(run_id, RunEventType.DONE, {"state": "failed"})
            _EMIT_LOCKS.pop(run_id, None)
            return
    watcher = asyncio.create_task(_make_cancel_watcher(run_id, cancel_event)())
    heart = asyncio.create_task(_heartbeat_loop(run_id, ending))
    pump = LogPump(run_id, publish)
    pump_task = asyncio.create_task(pump.drain())
    final = "failed"
    try:
        try:
            if kind == "demo":
                final = await run_demo(run_id, target, publish)
            elif kind == "agent":
                final = await _run_multi(run_id, target, "agent", publish, project_id=project_id or "unknown",
                                         cancel_event=cancel_event, on_line=pump.feed)
            else:
                final = await _run_multi(run_id, target, "scan", publish, project_id=project_id or "unknown",
                                         cancel_event=cancel_event, on_line=pump.feed)
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
        ending.set()          # stop the heartbeat only now that the terminal event is out
        cancel_event.set()
        watcher.cancel()
        heart.cancel()
        pump.stop()
        with contextlib.suppress(Exception):
            await pump.flush()
        pump_task.cancel()
        if _admitted and project_id:
            from nabu_agent.orchestration import admission
            with contextlib.suppress(Exception):
                await admission.release_run_slot(project_id, _profile_dir)
        _EMIT_LOCKS.pop(run_id, None)

async def _resolve_hosts(run_id: str, target: str, publish, *, project_id: str,
                         cancel_event, on_line, limits) -> list[str]:
    """Single host (no '/') -> [target]. CIDR -> alive-sweep, then clamp to the host guardrails."""
    if "/" not in target:
        return [target]
    from nabu_agent.engine import tools as etools
    from nabu_agent.engine.workspace import workspace_for

    await publish(RunEventType.LOG_LINE, {"line": f"[alive] sweeping {target} for live hosts"})
    sweep = await asyncio.to_thread(workspace_for(project_id, target).open_or_create)
    try:
        res = await asyncio.to_thread(etools.check_alive, sweep, target, on_line=on_line, cancel=cancel_event)
    except Exception as exc:
        await publish(RunEventType.LOG_LINE, {"line": f"[alive] sweep failed: {exc}"})
        return []
    hosts = list(res.get("hosts") or [])
    # SCOPE GUARD (defence in depth): only fan out to hosts actually inside the swept range. The
    # per-host guard's assert_in_scope is tautological (each host profile's scope == that host), so
    # this is the real backstop against the alive-parser ever yielding an address outside the CIDR.
    import ipaddress
    try:
        net = ipaddress.ip_network(target, strict=False)
        in_scope: list[str] = []
        for h in hosts:
            try:
                if ipaddress.ip_address(h) in net:
                    in_scope.append(h)
            except ValueError:
                continue  # unparseable host — drop it
        if len(in_scope) != len(hosts):
            await publish(RunEventType.LOG_LINE, {"line":
                f"[alive] dropped {len(hosts) - len(in_scope)} host(s) outside scope {target}"})
        hosts = in_scope
    except ValueError:
        pass  # target wasn't a parseable network (shouldn't happen — router validated scope)
    await publish(RunEventType.LOG_LINE, {"line": f"[alive] {len(hosts)} host(s) up in {target}"})
    if len(hosts) > limits.max_hosts:
        await publish(RunEventType.LOG_LINE,
                      {"line": f"[alive] capping to max_hosts={limits.max_hosts} (of {len(hosts)})"})
        hosts = hosts[: limits.max_hosts]
    return hosts


def _svc_node(host: str, s) -> str:
    """The map node id for a discovered service (host-scoped so a CIDR fan-out never collides)."""
    return f"svc-{host}-{s['port']}-{s.get('proto', 'tcp')}"


async def _scan_host(run_id: str, host: str, publish, *, project_id: str, cancel_event, on_line,
                     run_node: str, service_budget: int, alive_check: bool):
    """Shared per-host preamble for both recon kinds: emit the host node, open the host's OWN Profile,
    (optionally) alive-check, run the scan, then emit one service node per discovered service (capped
    to ``service_budget``). Returns ``(profile, services, svc_by_port)``."""
    from nabu_agent.engine import tools as etools
    from nabu_agent.engine.workspace import workspace_for

    host_node = f"host-{host}"
    await publish(RunEventType.TASK_CREATED, {"node_id": host_node, "node_state": NodeState.ACTIVE.value,
                  "kind": "host", "label": host, "parent": run_node})
    profile = await asyncio.to_thread(workspace_for(project_id, host).open_or_create)
    if alive_check:
        try:
            await asyncio.to_thread(etools.check_alive, profile, host, on_line=on_line, cancel=cancel_event)
        except Exception as exc:
            await publish(RunEventType.LOG_LINE, {"line": f"[alive] {host}: {exc}"})
    await asyncio.to_thread(etools.run_scan, profile, "default", on_line=on_line, cancel=cancel_event)
    await publish(RunEventType.TASK_UPDATED, {"node_id": host_node, "node_state": NodeState.DONE.value})

    services = etools.list_discovered_services(profile)["services"][:service_budget]
    svc_by_port: dict[int, str] = {}
    for s in services:
        nid = _svc_node(host, s)
        svc_by_port[int(s["port"])] = nid
        await publish(RunEventType.TASK_CREATED, {"node_id": nid, "node_state": NodeState.DONE.value,
                      "kind": "service", "label": f"{s['port']}/{s.get('service') or s.get('proto')}",
                      "parent": host_node})
    return profile, services, svc_by_port


async def _surface_findings(host: str, profile, publish, svc_by_port: dict[int, str]) -> None:
    """Emit a finding node for each row in the host's findings.json, edged from the enum agent that
    produced it. Shared by the deterministic and LLM host paths."""
    import oscprecon.findings as ef
    with contextlib.suppress(Exception):
        for i, f in enumerate(await asyncio.to_thread(ef.load_findings, profile.directory)):
            port = int(f.get("port") or 0)
            fid = f"finding-{host}-{port}-{i}"
            await publish(RunEventType.FINDING_ADDED, {
                "node_id": fid, "node_state": NodeState.DONE.value, "kind": "finding",
                "label": str(f.get("value", "finding"))[:40],
                "parent": svc_by_port.get(port, f"host-{host}"),
                "edges": [{"source": f"agent-enum-{host}-{port}", "target": fid, "label": "found"}]})


async def _recon_host(run_id: str, host: str, publish, *, project_id: str, cancel_event, on_line,
                      run_node: str, limits, service_budget: int) -> str:
    """Recon ONE host into its OWN Profile: host -> services -> concurrent enum (bounded by
    max_enum_per_host) -> findings -> per-host report. All map nodes are host-scoped."""
    from nabu_agent.engine import tools as etools

    profile, services, svc_by_port = await _scan_host(
        run_id, host, publish, project_id=project_id, cancel_event=cancel_event, on_line=on_line,
        run_node=run_node, service_budget=service_budget, alive_check=True)

    sem = asyncio.Semaphore(max(1, limits.max_enum_per_host))
    partial_flags: list[bool] = []

    async def _enum(s) -> None:
        agent_node = f"agent-enum-{host}-{s['port']}"
        service_name = s.get("service") or s.get("proto") or ""
        async with sem:
            if cancel_event.is_set():
                await publish(RunEventType.TASK_UPDATED, {"node_id": agent_node, "node_state": NodeState.STUCK.value})
                return
            await publish(RunEventType.TASK_CREATED, {"node_id": agent_node, "node_state": NodeState.ACTIVE.value,
                          "kind": "agent", "role": "enum", "label": f"enum {service_name}",
                          "parent": _svc_node(host, s)})
            try:
                await asyncio.to_thread(etools.enum_service, profile, service_name, "full",
                                        port=int(s["port"]), on_line=on_line, cancel=cancel_event)
                await publish(RunEventType.TASK_UPDATED, {"node_id": agent_node, "node_state": NodeState.DONE.value})
            except Exception as exc:
                partial_flags.append(True)
                await publish(RunEventType.TASK_UPDATED, {"node_id": agent_node, "node_state": NodeState.STUCK.value})
                await publish(RunEventType.LOG_LINE, {"line": f"[enum] {host}:{service_name}:{s['port']} — {exc}"})

    await asyncio.gather(*[_enum(s) for s in services], return_exceptions=True)
    await _surface_findings(host, profile, publish, svc_by_port)
    with contextlib.suppress(Exception):
        await asyncio.to_thread(etools.generate_report, profile, persist=True)
    return "partial" if (partial_flags or cancel_event.is_set()) else "done"


async def _agent_host(run_id: str, host: str, publish, *, project_id: str, cancel_event, on_line,
                      run_node: str, provider, limits, service_budget: int) -> str:
    """FULL LLM roster for ONE host: scan -> planner -> per-service enum agents -> per-service research
    agents -> reporter. Host-scoped, own Profile. Attacks are never an agent -- only a human gate."""
    from nabu_agent.agents.context import ContextAssembler
    from nabu_agent.agents.runner import AgentRunner
    from nabu_agent.engine import tools as etools

    host_node = f"host-{host}"
    partial = False

    async def emit(kind_: str, data: dict) -> None:
        await publish(RunEventType.LOG_LINE, data if kind_ == "log.line" else {"line": str(data)})

    async def run_role(role: str, node_id: str, label: str, parent: str, context: dict,
                       edges: list | None = None) -> dict | None:
        """Run one LLM agent role with its own live map node (active -> done / error)."""
        if cancel_event.is_set():
            return None
        await publish(RunEventType.TASK_CREATED, {"node_id": node_id, "node_state": NodeState.ACTIVE.value,
                      "kind": "agent", "role": role, "label": label, "parent": parent, "edges": edges or []})
        runner = AgentRunner(role, provider, project_id=project_id, target=host, run_id=run_id,
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

    profile, services, svc_by_port = await _scan_host(
        run_id, host, publish, project_id=project_id, cancel_event=cancel_event, on_line=on_line,
        run_node=run_node, service_budget=service_budget, alive_check=False)
    planner_node = f"agent-planner-{host}"

    # --- planner ---
    base_ctx = await ContextAssembler(project_id, host).build()
    if await run_role("planner", planner_node, "planner", host_node, base_ctx) is None:
        partial = True

    sem = asyncio.Semaphore(max(1, limits.max_enum_per_host))

    def _svc_ctx(s) -> dict:
        return {**base_ctx, "host": host, "port": s["port"],
                "service": {"port": s["port"], "service": s.get("service", ""),
                            "product": s.get("product", "")}}

    # --- enum agents (one per service, concurrent) ---
    async def _enum(s) -> dict | None:
        async with sem:
            return await run_role("enum_writer", f"agent-enum-{host}-{s['port']}",
                                  f"enum {s.get('service') or s['port']}", _svc_node(host, s), _svc_ctx(s),
                                  edges=[{"source": planner_node, "target": f"agent-enum-{host}-{s['port']}",
                                          "label": "dispatch"}])
    enum_res = await asyncio.gather(*[_enum(s) for s in services], return_exceptions=True)
    if any(r is None or isinstance(r, Exception) for r in enum_res):
        partial = True
    if cancel_event.is_set():
        return "cancelled"

    await _surface_findings(host, profile, publish, svc_by_port)

    # --- research agents (one per service, concurrent; proposals only) ---
    research_ctx = await ContextAssembler(project_id, host).build()

    async def _research(s) -> dict | None:
        ctx = {**research_ctx, "host": host, "port": s["port"],
               "finding": {"service": s.get("service", ""), "port": s["port"],
                           "product": s.get("product", "")}}
        async with sem:
            return await run_role("research", f"agent-research-{host}-{s['port']}",
                                  f"research {s.get('service') or s['port']}", _svc_node(host, s), ctx,
                                  edges=[{"source": f"agent-enum-{host}-{s['port']}",
                                          "target": f"agent-research-{host}-{s['port']}", "label": "feeds"}])
    await asyncio.gather(*[_research(s) for s in services], return_exceptions=True)
    if cancel_event.is_set():
        return "cancelled"

    # --- reporter (this host's agents converge -> per-host report) ---
    report_node = f"agent-report-{host}"
    report_edges = [{"source": planner_node, "target": report_node, "label": "feeds"}]
    for s in services:
        report_edges.append({"source": f"agent-enum-{host}-{s['port']}", "target": report_node, "label": "feeds"})
        report_edges.append({"source": f"agent-research-{host}-{s['port']}", "target": report_node, "label": "feeds"})
    report_ctx = await ContextAssembler(project_id, host).build()
    await run_role("reporter", report_node, "report writer", host_node, report_ctx, edges=report_edges)
    with contextlib.suppress(Exception):
        await asyncio.to_thread(etools.generate_report, profile, persist=True)
    return "partial" if partial else "done"


async def _run_multi(run_id: str, target: str, kind: str, publish, *, project_id: str,
                     cancel_event, on_line=None) -> str:
    """The multi-host recon driver, shared by the deterministic ('scan') and LLM ('agent') kinds.
    Single host -> one per-host job; a CIDR -> alive-sweep -> per-host fan-out under the RunLimits
    host guardrails (max_hosts / max_concurrent_hosts / max_enum_per_host / max_total_tasks). The
    supervisor owns the single terminal state; per-host work runs in-process or, with NABU_USE_ARQ,
    as one recon_host_job each. 'agent' requires NABU_LLM_BASE_URL and fails cleanly without it."""
    from nabu_agent.orchestration.limits import RunLimits

    run_node = f"run-{run_id}"
    await publish(RunEventType.RUN_STATUS, {"node_id": run_node, "node_state": NodeState.ACTIVE.value,
                  "state": "scanning", "label": "recon run"})

    provider = None
    if kind == "agent":
        from nabu_agent.llm.factory import build_provider
        from nabu_agent.settings import get_settings
        settings = get_settings()
        if not settings.llm.base_url:
            await publish(RunEventType.ERROR, {"message": "no LLM configured — set NABU_LLM_BASE_URL to "
                          "your internal OpenAI-compatible endpoint (kind='demo' needs no brain)."})
            return "failed"
        provider = build_provider(settings.llm)

    limits = RunLimits()
    hosts = await _resolve_hosts(run_id, target, publish, project_id=project_id,
                                 cancel_event=cancel_event, on_line=on_line, limits=limits)
    if not hosts:
        await publish(RunEventType.LOG_LINE, {"line": "[scan] no live hosts to recon"})
        return "failed"

    stop = await _gate_host_fanout(run_id, target, hosts, publish, project_id=project_id,
                                   cancel_event=cancel_event)
    if stop:
        return stop

    per_host_budget = max(1, limits.max_total_tasks // len(hosts))  # global hosts x services cap
    host_sem = asyncio.Semaphore(max(1, limits.max_concurrent_hosts))

    async def _one(host: str):
        async with host_sem:
            if cancel_event.is_set():
                return "cancelled"
            try:
                return await _dispatch_host(run_id, host, kind, publish, project_id=project_id,
                                            cancel_event=cancel_event, on_line=on_line, run_node=run_node,
                                            limits=limits, service_budget=per_host_budget, provider=provider)
            except Exception as exc:  # one host crashing must not sink the whole run
                await publish(RunEventType.TASK_UPDATED,
                              {"node_id": f"host-{host}", "node_state": NodeState.ERROR.value})
                await publish(RunEventType.LOG_LINE, {"line": f"[host] {host} failed: {exc}"})
                return exc

    results = await asyncio.gather(*[_one(h) for h in hosts])
    if cancel_event.is_set():
        return "cancelled"
    errors = [r for r in results if isinstance(r, Exception)]
    if errors and len(errors) == len(hosts):
        raise errors[0]  # every host failed -> surface as a driver failure (ERROR event + state=failed)
    partial = bool(errors) or any(r in (None, "partial", "cancelled") for r in results)

    if kind != "agent":  # the LLM path already emits a per-host reporter node; scan gets a run-level one
        report_node = f"report-{run_id}"
        await publish(RunEventType.TASK_CREATED, {"node_id": report_node, "node_state": NodeState.ACTIVE.value,
                      "kind": "report", "label": f"report ({len(hosts)} host(s))", "parent": run_node})
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




# --- Phase A: human-gated spray/exploit EXECUTION -----------------------------------------------
# A proposed spray/exploit becomes a Checkpoint; a human approves it (double gate: platform switch +
# per-project toggle + operator approval, plus exploit_confirmed / a chosen credential). Approval
# ENQUEUES this job (no live driver coroutine is holding — the recon run may already be terminal).
# It re-verifies everything and hands the action to the ONE gated door. The checkpoint stores only
# which action (service + action_id), NEVER a command string — the command is re-derived here from
# the catalog, so a forged/edited command can't reach the executor.

def _gated_values(profile: Any, service: str, *, params: dict | None = None,
                  credential: Any = None, redact_secret: bool = False) -> dict[str, str]:
    """The template fill values for a gated action: the profile's target, the discovered service's
    port, any operator-supplied ``params``, and — for a chosen credential — its fields mapped onto
    the ``{user}``/``{password}``/``{hash}``/``{domain}`` placeholders (redacted when
    ``redact_secret`` so a preview never leaks the plaintext). Later sources win on conflict."""
    from nabu_agent.agents.tools.dispatch import _evidence_from_profile
    from nabu_agent.engine.creds_ref import credential_values

    values: dict[str, str] = dict(_evidence_from_profile(profile).get("values") or {})
    for s in getattr(profile, "discovered_services", []):
        if str(getattr(s, "service", "")) == service and getattr(s, "port", None):
            values["port"] = str(s.port)
            break
    if params:
        values.update({str(k): str(v) for k, v in params.items() if str(v)})
    if credential is not None:
        values.update(credential_values(credential, redact=redact_secret))
    return values


def _resolve_gated_command(profile: Any, service: str, action_id: str, *,
                           params: dict | None = None, credential: Any = None,
                           redact_secret: bool = False) -> str:
    """Re-derive the exact shell line for a gated action FROM THE CATALOG, server-side.

    Rebuilds the ranking evidence from the profile's own discovered state, fills the action template
    with :func:`_gated_values` (target + port + operator params + the chosen credential), looks the
    action up by id, and returns the pre-filled command ONLY if it is attacker-runnable and every
    placeholder resolved. Anything else raises ``ValueError`` (the gate stays closed). With
    ``redact_secret`` the returned command carries the secret's redaction marker, not the plaintext
    — used for previews and log lines; execution passes ``redact_secret=False``."""
    from nabu_agent.agents.tools.dispatch import _evidence_from_profile
    from nabu_agent.engine import tools as etools

    evidence = _evidence_from_profile(profile)
    evidence["values"] = _gated_values(profile, service, params=params, credential=credential,
                                       redact_secret=redact_secret)
    catalog = etools.catalog_actions_for(service, evidence)
    for a in catalog.get("actions", []):
        if a["id"] != action_id:
            continue
        if not a.get("executable"):
            raise ValueError(f"action {action_id!r} is not attacker-runnable")
        if a.get("unfilled"):
            raise ValueError(f"needs: {', '.join(a['unfilled'])}")
        cmd = (a.get("command") or "").strip()
        if not cmd:
            raise ValueError(f"action {action_id!r} produced an empty command")
        return cmd
    raise ValueError(f"action {action_id!r} not found in the {service!r} catalog")


def _record_credential_tested(profile: Any, credential: Any, target: str) -> None:
    """Best-effort: append ``target`` to the used credential's ``tested_against`` after a spray/exploit
    (mirrors what a manual run would record). Never raises."""
    import contextlib as _cl
    with _cl.suppress(Exception):
        if credential is None or target in getattr(credential, "tested_against", []):
            return
        from dataclasses import replace
        updated = replace(credential, tested_against=[*credential.tested_against, target])
        profile.replace_credential(credential, updated)


async def _try_set_state(run_id: str, dst: str) -> None:
    """Best-effort run-state transition, guarded by the state machine. A terminal run (e.g. a
    finished recon run the operator is attacking after the fact) is left as-is — the checkpoint and
    the attack map node carry the attack's own lifecycle."""
    from nabu_agent.orchestration.states import RunState, can_transition
    async with sessionmaker()() as db:
        run = (await db.execute(select(Run).where(Run.id == run_id))).scalar_one_or_none()
        if not run:
            return
        try:
            src, target_state = RunState(run.state), RunState(dst)
        except ValueError:
            return
        if can_transition(src, target_state):
            run.state = dst
            await db.commit()


async def _set_checkpoint_status(cp_id: str, status: str) -> None:
    from nabu_agent.db.models import Checkpoint
    async with sessionmaker()() as db:
        cp = (await db.execute(select(Checkpoint).where(Checkpoint.id == cp_id))).scalar_one_or_none()
        if cp:
            cp.status = status
            await db.commit()


async def _record_attack_summary(run_id: str, entry: dict[str, Any]) -> None:
    """Append one executed gated action to the run's summary (a durable record beside the events)."""
    with contextlib.suppress(Exception):
        async with sessionmaker()() as db:
            run = (await db.execute(select(Run).where(Run.id == run_id))).scalar_one_or_none()
            if run is None:
                return
            summary = dict(run.summary or {})
            summary["attacks"] = [*summary.get("attacks", []), entry]
            run.summary = summary
            await db.commit()


async def execute_approved_action(checkpoint_id: str) -> str:
    """Execute ONE human-approved spray/exploit checkpoint through the single gated door (Phase A of
    the attack gate — human-driven, no LLM). Never raises: a gate/derive/door failure marks the
    checkpoint FAILED and paints a red attack node. Returns ``"<cp_id>:<outcome>"``."""
    from types import SimpleNamespace

    from nabu_agent.db.models import Checkpoint, Project
    from nabu_agent.engine import shell_gateway as sg
    from nabu_agent.engine.errors import AttackGateClosed
    from nabu_agent.engine.workspace import workspace_for
    from nabu_agent.orchestration.limits import RunLimits
    from nabu_agent.settings import get_settings

    async with sessionmaker()() as db:
        cp = (await db.execute(select(Checkpoint).where(Checkpoint.id == checkpoint_id))).scalar_one_or_none()
        if cp is None:
            return f"{checkpoint_id}:missing"
        run = (await db.execute(select(Run).where(Run.id == cp.run_id))).scalar_one_or_none()
        project = None
        if run is not None:
            project = (await db.execute(
                select(Project).where(Project.id == run.project_id))).scalar_one_or_none()
        kind, target, action_id = cp.kind, cp.target, cp.action_id
        status, approved_by = cp.status, cp.approved_by
        exploit_confirmed = bool(cp.exploit_confirmed)
        requires = cp.requires or {}
        service = requires.get("service", "")
        params = requires.get("params") or {}
        credential_ref = cp.credential_ref
        run_id = cp.run_id
        project_id = run.project_id if run else None
        spray_gate = bool(project.spray_enabled) if project else False
        exploit_gate = bool(project.exploit_enabled) if project else False

    # Re-verify the approval + linkage (never trust the enqueuer).
    if status != "approved" or not approved_by:
        return f"{checkpoint_id}:not-approved"
    if kind not in ("spray", "exploit"):
        return f"{checkpoint_id}:bad-kind"
    if run is None or project is None or not project_id:
        await _set_checkpoint_status(checkpoint_id, "failed")
        return f"{checkpoint_id}:orphan"

    node = f"attack-{checkpoint_id}"

    async def publish(type_: RunEventType, data: dict[str, Any]) -> None:
        await _emit(run_id, type_, data)

    cancel_event = threading.Event()
    ending = threading.Event()
    watcher = asyncio.create_task(_make_cancel_watcher(run_id, cancel_event)())
    pump = LogPump(run_id, publish)
    pump_task = asyncio.create_task(pump.drain())
    hb = asyncio.create_task(_heartbeat_loop(run_id, ending))
    await _touch_heartbeat(run_id)

    await _set_checkpoint_status(checkpoint_id, "executing")
    await _try_set_state(run_id, "executing_approved")
    await publish(RunEventType.TASK_CREATED, {"node_id": node, "node_state": NodeState.ACTIVE.value,
                  "label": f"{kind}: {action_id}", "attack": True, "kind": kind, "target": target})

    outcome = "executed"
    try:
        s = get_settings()
        platform_gate = s.spray_enabled if kind == "spray" else s.exploit_enabled
        project_gate = spray_gate if kind == "spray" else exploit_gate
        if not platform_gate:
            raise AttackGateClosed(f"{kind} is disabled platform-wide (set NABU_{kind.upper()}_ENABLED)")
        if not project_gate:
            raise AttackGateClosed(f"{kind} is not enabled for this project")

        # Open the target's OWN profile, resolve the chosen credential from the vault (server-side,
        # never from the checkpoint), and RE-DERIVE the command from the catalog. The secret reaches
        # only shell.run; the log line + events carry the REDACTED command.
        from nabu_agent.engine.creds_ref import resolve_credential

        profile = await asyncio.to_thread(workspace_for(project_id, target).open)
        credential = await asyncio.to_thread(resolve_credential, profile, credential_ref)
        if credential_ref and credential is None:
            raise AttackGateClosed("the chosen credential is no longer in the vault")
        shell_line = await asyncio.to_thread(
            _resolve_gated_command, profile, service, action_id, params=params, credential=credential)
        redacted = await asyncio.to_thread(
            _resolve_gated_command, profile, service, action_id, params=params,
            credential=credential, redact_secret=True)
        await publish(RunEventType.LOG_LINE, {"lines":
            [f"[{kind}] approved by {approved_by}; scope re-checked; running: {redacted}"]})

        # The ONE gated door: it independently re-verifies the approval, re-validates scope, and is
        # the sole place spray=/exploit=True is set.
        cp_like = SimpleNamespace(status="approved", approved_by=approved_by, kind=kind,
                                  target=target, exploit_confirmed=exploit_confirmed)
        out_file = profile.directory / f"attack-{checkpoint_id}.log"
        result = await asyncio.to_thread(
            sg.execute_gated_action, cp_like, profile, shell_line, out_file,
            on_line=pump.feed, cancel=cancel_event, timeout=float(RunLimits().host_job_timeout_s))

        blocked = bool(result.get("blocked"))
        exit_code = result.get("exit_code")
        outcome = "blocked" if blocked else "executed"
        node_state = NodeState.ERROR if blocked else NodeState.DONE
        await pump.flush()
        if not blocked and credential is not None:
            await asyncio.to_thread(_record_credential_tested, profile, credential, target)
        await _record_attack_summary(run_id, {"checkpoint_id": checkpoint_id, "kind": kind,
                                     "target": target, "action_id": action_id, "outcome": outcome})
        await publish(RunEventType.TASK_UPDATED, {"node_id": node, "node_state": node_state.value,
                      "attack": True, "exit_code": exit_code, "blocked": blocked})
        await publish(RunEventType.LOG_LINE, {"lines": [f"[{kind}] finished: exit={exit_code} blocked={blocked}"]})
        await _set_checkpoint_status(checkpoint_id, "executed")
        await _try_set_state(run_id, "report_ready")
    except Exception as exc:  # noqa: BLE001 - a gate/derive/door failure must fail the action safely, not crash the worker
        outcome = "failed"
        with contextlib.suppress(Exception):
            await pump.flush()
        await publish(RunEventType.ERROR, {"node_id": node, "node_state": NodeState.ERROR.value,
                      "attack": True, "message": f"{kind} gate closed: {exc}"})
        await _set_checkpoint_status(checkpoint_id, "failed")
        await _try_set_state(run_id, "partial")
        _log.warning("attack-execute-failed", checkpoint_id=checkpoint_id, kind=kind, exc_info=True)
    finally:
        ending.set()
        cancel_event.set()
        watcher.cancel()
        pump.stop()
        pump_task.cancel()
        with contextlib.suppress(Exception):
            await hb

    with contextlib.suppress(Exception):  # app-level audit (the gated shell is engine-audited in the door)
        from nabu_agent import audit as app_audit
        await app_audit.record(actor_user_id=approved_by, action=app_audit.ATTACK_EXECUTED,
                               object_type="checkpoint", object_id=checkpoint_id, project_id=project_id,
                               details={"kind": kind, "target": target, "action_id": action_id, "outcome": outcome})
    return f"{checkpoint_id}:{outcome}"
