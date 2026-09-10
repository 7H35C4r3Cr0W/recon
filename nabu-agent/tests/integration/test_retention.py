"""Retention + quotas: old terminal run_events are pruned (live runs spared), each project is trimmed
to its newest N runs, and the admin-only endpoints work (non-admins get 403)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import func, select

pytestmark = pytest.mark.asyncio


async def test_event_ttl_prunes_old_terminal_events_only(app_ctx):
    from nabu_agent.db.models import Run, RunEvent
    from nabu_agent.db.session import sessionmaker
    from nabu_agent.orchestration.retention import run_retention

    old = datetime.now(timezone.utc) - timedelta(days=60)
    async with sessionmaker()() as db:
        done = Run(project_id="p", kind="scan", target="10.0.0.1", state="done")
        live = Run(project_id="p", kind="scan", target="10.0.0.2", state="scanning")
        db.add_all([done, live]); await db.flush()
        db.add(RunEvent(run_id=done.id, seq=1, type="log.line", payload={}, ts=old))   # prune
        db.add(RunEvent(run_id=done.id, seq=2, type="done", payload={}))               # keep (recent)
        db.add(RunEvent(run_id=live.id, seq=1, type="log.line", payload={}, ts=old))   # keep (live)
        await db.commit(); did, lid = done.id, live.id

    out = await run_retention(run_events_days=30, max_runs_per_project=1000)
    assert out["run_events_deleted"] >= 1
    async with sessionmaker()() as db:
        done_evts = (await db.execute(select(func.count()).select_from(RunEvent).where(RunEvent.run_id == did))).scalar()
        live_evts = (await db.execute(select(func.count()).select_from(RunEvent).where(RunEvent.run_id == lid))).scalar()
    assert done_evts == 1   # old pruned, recent 'done' kept
    assert live_evts == 1   # a live run's old event is NOT pruned


async def test_per_project_run_cap(app_ctx):
    from nabu_agent.db.models import Run
    from nabu_agent.db.session import sessionmaker
    from nabu_agent.orchestration.retention import run_retention

    base = datetime.now(timezone.utc)
    async with sessionmaker()() as db:
        for i in range(5):
            db.add(Run(project_id="capproj", kind="scan", target=f"10.0.0.{i}", state="done",
                       started_at=base - timedelta(minutes=5 - i)))  # i=4 newest
        await db.commit()
    out = await run_retention(run_events_days=9999, max_runs_per_project=2)
    assert out["runs_pruned"] == 3
    async with sessionmaker()() as db:
        remaining = (await db.execute(select(func.count()).select_from(Run).where(Run.project_id == "capproj"))).scalar()
    assert remaining == 2


async def test_admin_endpoints_require_admin(app_ctx):
    app, admin = app_ctx
    a = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    await a.post("/api/auth/login", json=admin)
    assert (await a.get("/api/admin/storage")).status_code == 200
    assert "run_events" in (await a.get("/api/admin/storage")).json()
    assert (await a.post("/api/admin/retention")).status_code == 200

    # a non-admin operator is refused
    from nabu_agent.auth.providers import hash_password
    from nabu_agent.db.models import User
    from nabu_agent.db.session import sessionmaker
    async with sessionmaker()() as db:
        db.add(User(email="op@x.io", display_name="op", role="operator", auth_source="local",
                    password_hash=hash_password("pw")))
        await db.commit()
    b = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    await b.post("/api/auth/login", json={"email": "op@x.io", "password": "pw"})
    assert (await b.get("/api/admin/storage")).status_code == 403
    assert (await b.post("/api/admin/retention")).status_code == 403
    await a.aclose(); await b.aclose()
