"""Stale-run reaper — marks non-terminal runs whose heartbeat has gone stale as failed and emits a
terminal event, so a run whose worker was killed (OOM / SIGKILL / eviction) doesn't stay stuck.

A running run beats its `heartbeat_at` every ~10s (services.runs._heartbeat_loop); a run row is also
created with a heartbeat so a never-picked-up queued run (worker/queue down) also goes stale. The
reaper runs as an Arq cron on the worker (every ~30s) and once at API startup.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select

from nabu_agent.db.models import Run
from nabu_agent.db.session import sessionmaker
from nabu_agent.settings import get_settings

_log = structlog.get_logger("nabu_agent.reaper")

_TERMINAL = ("done", "partial", "failed", "cancelled")


async def reap_stale_runs(threshold_s: int | None = None) -> list[str]:
    """Fail every non-terminal run whose heartbeat is older than the threshold; emit a terminal DONE
    for each (so live viewers unblock). Returns the reaped run ids. Best-effort + never raises."""
    threshold = threshold_s if threshold_s is not None else get_settings().run_stale_after_s
    cutoff = datetime.now(UTC) - timedelta(seconds=threshold)
    reaped: list[str] = []
    reaped_pids: dict[str, str] = {}
    try:
        async with sessionmaker()() as db:
            rows = (await db.execute(select(Run).where(
                Run.state.notin_(_TERMINAL), Run.heartbeat_at.is_not(None), Run.heartbeat_at < cutoff
            ))).scalars().all()
            for run in rows:
                run.state = "failed"
                run.error = "reaped: worker heartbeat stale — the worker running this run likely died"
                run.finished_at = datetime.now(UTC)
                reaped.append(run.id)
                if run.project_id:
                    reaped_pids[run.id] = run.project_id
            if reaped:
                await db.commit()
    except Exception:
        _log.error("reaper-query-failed", exc_info=True)
        return []

    if reaped:
        _log.warning("runs-reaped", count=len(reaped), run_ids=reaped, threshold_s=threshold)
        # a dead worker never ran execute_run's finally, so its admission slot (Redis project mutex +
        # global-active counter) was never released — reconcile it here, or the project stays locked
        # (up to the mutex TTL) and the global ceiling leaks a permanent +1 per crash.
        from nabu_agent.engine.workspace import project_root
        from nabu_agent.events.schema import RunEventType
        from nabu_agent.orchestration import admission
        from nabu_agent.services.runs import _emit
        for rid in reaped:
            pid = reaped_pids.get(rid)
            if pid:
                with contextlib.suppress(Exception):
                    await admission.release_run_slot(pid, str(project_root(pid)))
            # emit a terminal event so any connected live view stops waiting
            with contextlib.suppress(Exception):
                await _emit(rid, RunEventType.ERROR, {"message": "run reaped: worker died"})
                await _emit(rid, RunEventType.DONE, {"state": "failed", "reaped": True})
    return reaped


async def reap_job(ctx: dict[str, Any]) -> int:
    """Arq cron entrypoint. Returns the number of runs reaped."""
    return len(await reap_stale_runs())
