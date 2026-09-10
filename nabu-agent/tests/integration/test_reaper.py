"""Stale-run reaper: a run whose worker died (stale heartbeat) is marked failed and gets a terminal
event so the live view unblocks; a run with a fresh heartbeat is left alone."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

pytestmark = pytest.mark.asyncio


async def test_reaper_fails_stale_but_not_fresh(app_ctx):
    from nabu_agent.db.models import Run
    from nabu_agent.db.session import sessionmaker
    from nabu_agent.orchestration.reaper import reap_stale_runs
    from nabu_agent.services.runs import replay_events

    now = datetime.now(UTC)
    async with sessionmaker()() as db:
        stale = Run(project_id="p", kind="scan", target="10.0.0.1", state="scanning",
                    heartbeat_at=now - timedelta(seconds=300))
        fresh = Run(project_id="p", kind="scan", target="10.0.0.2", state="scanning",
                    heartbeat_at=now)
        done = Run(project_id="p", kind="scan", target="10.0.0.3", state="done",
                   heartbeat_at=now - timedelta(seconds=300))  # terminal → never reaped
        db.add_all([stale, fresh, done])
        await db.commit()
        sid, fid, did = stale.id, fresh.id, done.id

    reaped = await reap_stale_runs(threshold_s=120)
    assert sid in reaped and fid not in reaped and did not in reaped

    async with sessionmaker()() as db:
        assert (await db.get(Run, sid)).state == "failed"
        assert "reaped" in (await db.get(Run, sid)).error
        assert (await db.get(Run, fid)).state == "scanning"
        assert (await db.get(Run, did)).state == "done"
        evs = await replay_events(db, sid)
    # a terminal DONE was emitted for the reaped run
    assert any(e["type"] == "done" for e in evs)
