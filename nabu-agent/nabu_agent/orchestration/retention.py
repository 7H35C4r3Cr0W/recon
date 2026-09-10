"""Data retention + per-project quotas (housekeeping).

Two policies, both best-effort and safe to re-run:
  1. **Event TTL** — delete the durable ``run_events`` (the WS replay feed) of TERMINAL runs older
     than ``retention_run_events_days``. The report + findings remain; only the noisy event stream is
     pruned. Live runs are never touched.
  2. **Per-project run cap** — keep only the newest ``max_runs_per_project`` runs per project; older
     runs are deleted along with their children (run_events / agent_tasks / checkpoints).

Runs as an Arq cron on the worker (hourly + at startup) and via an admin endpoint. Models have no
ON DELETE CASCADE, so children are deleted before their run.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import delete, func, select

from nabu_agent.db.models import AgentTask, Checkpoint, Run, RunEvent
from nabu_agent.db.session import sessionmaker
from nabu_agent.settings import get_settings

_log = structlog.get_logger("nabu_agent.retention")
_TERMINAL = ("done", "partial", "failed", "cancelled")


async def run_retention(*, run_events_days: int | None = None,
                        max_runs_per_project: int | None = None) -> dict[str, int]:
    """Apply the retention policies. Returns counts. Never raises."""
    s = get_settings()
    ev_days = run_events_days if run_events_days is not None else s.retention_run_events_days
    cap = max_runs_per_project if max_runs_per_project is not None else s.max_runs_per_project
    cutoff = datetime.now(UTC) - timedelta(days=ev_days)
    deleted_events = 0
    pruned_runs = 0
    try:
        async with sessionmaker()() as db:
            # 1) event TTL — only for terminal runs, so a long-running run's replay is safe
            terminal_run_ids = select(Run.id).where(Run.state.in_(_TERMINAL))
            res = await db.execute(delete(RunEvent).where(
                RunEvent.ts < cutoff, RunEvent.run_id.in_(terminal_run_ids)))
            deleted_events += res.rowcount or 0

            # 2) per-project run cap — delete the oldest runs beyond the newest `cap`, + children
            project_ids = (await db.execute(select(Run.project_id).distinct())).scalars().all()
            for pid in project_ids:
                old_ids = (await db.execute(
                    select(Run.id).where(Run.project_id == pid)
                    .order_by(Run.started_at.desc()).offset(cap))).scalars().all()
                if not old_ids:
                    continue
                await db.execute(delete(RunEvent).where(RunEvent.run_id.in_(old_ids)))
                await db.execute(delete(Checkpoint).where(Checkpoint.run_id.in_(old_ids)))
                await db.execute(delete(AgentTask).where(AgentTask.run_id.in_(old_ids)))
                res = await db.execute(delete(Run).where(Run.id.in_(old_ids)))
                pruned_runs += res.rowcount or len(old_ids)
            await db.commit()
    except Exception:
        _log.error("retention-failed", exc_info=True)
        return {"run_events_deleted": deleted_events, "runs_pruned": pruned_runs, "error": 1}
    if deleted_events or pruned_runs:
        _log.info("retention-ran", run_events_deleted=deleted_events, runs_pruned=pruned_runs)
    return {"run_events_deleted": deleted_events, "runs_pruned": pruned_runs}


async def storage_stats() -> dict[str, int]:
    """Row counts for the growth-prone tables (admin visibility)."""
    async with sessionmaker()() as db:
        async def _count(model) -> int:
            return int((await db.execute(select(func.count()).select_from(model))).scalar() or 0)
        return {"runs": await _count(Run), "run_events": await _count(RunEvent),
                "agent_tasks": await _count(AgentTask), "checkpoints": await _count(Checkpoint)}


async def retention_job(ctx: dict[str, Any]) -> dict[str, int]:
    """Arq cron entrypoint."""
    if not get_settings().retention_enabled:
        return {"skipped": 1}
    return await run_retention()
