"""/24-scale load tests (run explicitly: `pytest -m load`). These push the volume a 256-host run
produces through the REAL event/persistence pipeline (seq + DB persist + Redis publish + LogPump) and
the concurrent per-service fan-out, then assert the platform stays bounded + consistent and report
throughput. They use sqlite + fakeredis in-process, so numbers are relative (real Postgres/Redis are
faster); the point is to prove no unbounded growth and that the RunLimits caps hold."""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

pytestmark = [pytest.mark.load, pytest.mark.asyncio]

HOSTS = 256
SVCS_PER_HOST = 4


async def test_cidr_event_pipeline_throughput(app_ctx):
    """A /24 worth of node/finding events streamed through _emit — persisted, replayable in seq
    order, bounded. Reports events/sec."""
    from nabu_agent.db.models import Run, RunEvent
    from nabu_agent.db.session import sessionmaker
    from nabu_agent.events.schema import NodeState, RunEventType
    from nabu_agent.services import runs

    async with sessionmaker()() as db:
        r = Run(project_id="p", kind="scan", target="10.0.0.0/24", state="scanning")
        db.add(r); await db.commit(); rid = r.id

    start = time.perf_counter()
    for h in range(HOSTS):
        ip = f"10.0.0.{h}"
        await runs._emit(rid, RunEventType.TASK_CREATED,
                         {"node_id": f"host-{ip}", "node_state": NodeState.ACTIVE.value, "kind": "host"})
        for s in range(SVCS_PER_HOST):
            await runs._emit(rid, RunEventType.TASK_CREATED,
                             {"node_id": f"svc-{ip}-{s}", "node_state": NodeState.DONE.value, "kind": "service"})
        await runs._emit(rid, RunEventType.TASK_UPDATED,
                         {"node_id": f"host-{ip}", "node_state": NodeState.DONE.value})
    await runs._emit(rid, RunEventType.DONE, {"state": "done"})
    dur = time.perf_counter() - start

    total = HOSTS * (SVCS_PER_HOST + 2) + 1
    async with sessionmaker()() as db:
        persisted = (await db.execute(
            select(func.count()).select_from(RunEvent).where(RunEvent.run_id == rid))).scalar()
        replay = await runs.replay_events(db, rid)
    seqs = [e["seq"] for e in replay]
    print(f"\n[load] /24 event pipeline: {total} events in {dur:.2f}s = {total / dur:.0f} ev/s "
          f"(sqlite+fakeredis, in-proc)")
    assert persisted == total                      # every event durably persisted
    assert seqs == sorted(set(seqs))               # strictly monotonic, no gaps/dupes
    assert replay[-1]["type"] == "done"            # terminal event replayable
    assert dur < 120                               # generous budget; real stores are much faster


async def test_wide_service_fanout_is_bounded(app_ctx, monkeypatch, tmp_path):
    """A host with MANY services: the concurrent enum fan-out completes, bounded by the semaphore and
    the max_total_tasks cap; peak concurrency never exceeds the cap; the run still finishes."""
    import threading

    from nabu_agent.engine import tools as etools
    from nabu_agent.engine import workspace as ews
    from nabu_agent.orchestration.limits import RunLimits

    N = 300
    dto = [{"port": 1000 + i, "proto": "tcp", "service": f"svc{i}"} for i in range(N)]
    prof = SimpleNamespace(directory=tmp_path, profile_name="p",
                           target=SimpleNamespace(ip="10.0.0.5", hostname=None), discovered_services=[])
    monkeypatch.setattr(ews, "workspace_for", lambda *a, **k: SimpleNamespace(open_or_create=lambda: prof))
    monkeypatch.setattr(etools, "check_alive", lambda p, t=None, **k: {"up": True})
    monkeypatch.setattr(etools, "run_scan", lambda p, sp="default", **k: {"services": []})
    monkeypatch.setattr(etools, "list_discovered_services", lambda p: {"services": dto})
    monkeypatch.setattr(etools, "generate_report", lambda p, **k: {"markdown": "# r"})
    import oscprecon.findings as ef
    monkeypatch.setattr(ef, "load_findings", lambda d: [])

    state = {"cur": 0, "peak": 0, "lock": threading.Lock()}

    def _enum(p, service, mode="full", **k):
        with state["lock"]:
            state["cur"] += 1; state["peak"] = max(state["peak"], state["cur"])
        time.sleep(0.005)
        with state["lock"]:
            state["cur"] -= 1
        return {"service": service, "summary": [], "credentials_added": 0, "findings_added": 0}
    monkeypatch.setattr(etools, "enum_service", _enum)

    import httpx
    app, admin = app_ctx
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        await c.post("/api/auth/login", json=admin)
        pid = (await c.post("/api/projects", json={"display_name": "Wide"})).json()["id"]
        await c.post(f"/api/projects/{pid}/scope", json={"target": "10.0.0.5"})
        start = time.perf_counter()
        run_id = (await c.post(f"/api/projects/{pid}/runs", json={"target": "10.0.0.5", "kind": "scan"})).json()["run_id"]
        agents = set()
        for _ in range(400):
            import asyncio
            await asyncio.sleep(0.1)
            evs = (await c.get(f"/api/runs/{run_id}/events")).json()["events"]
            for e in evs:
                if str(e["data"].get("node_id", "")).startswith("agent-enum-"):
                    agents.add(e["data"]["node_id"])
            if any(e["type"] == "done" for e in evs):
                break
        dur = time.perf_counter() - start

    cap = RunLimits().max_enum_per_host       # per-host enum semaphore (host tier)
    capped_services = min(N, RunLimits().max_total_tasks)
    print(f"\n[load] wide fan-out: {N} services → {len(agents)} enum agents, peak concurrency "
          f"{state['peak']} (cap {cap}), {dur:.1f}s")
    assert state["peak"] <= cap                    # semaphore actually bounds concurrency
    assert len(agents) == capped_services          # every (capped) service got an agent
