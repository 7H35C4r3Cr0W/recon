"""Activity feed — a per-user "what's happening" view aggregated across the projects the caller can
see (owned / member / admin→all). Read-only, derived from the runs + run_events tables (no extra
store): recent runs with state, target, kind, a finding count, and an 'attention' flag for runs that
need a human (awaiting_approval) or failed. The unread badge counts live + attention runs.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent.auth.deps import get_current_user
from nabu_agent.db.models import Project, ProjectMember, Run, RunEvent, User
from nabu_agent.db.session import get_db

router = APIRouter(tags=["feed"])

_TERMINAL = {"done", "partial", "failed", "cancelled"}
_ATTENTION = {"awaiting_approval", "failed"}


async def _visible_project_ids(db: AsyncSession, user: User) -> list[str] | None:
    """Project ids the user may see; None means 'all' (global admin)."""
    if user.role == "admin":
        return None
    member = select(ProjectMember.project_id).where(ProjectMember.user_id == user.id)
    rows = (await db.execute(select(Project.id).where(
        or_(Project.owner_id == user.id, Project.id.in_(member))))).scalars().all()
    return list(rows)


@router.get("/feed")
async def feed(limit: int = 50, db: AsyncSession = Depends(get_db),
               user: User = Depends(get_current_user)) -> dict:
    limit = max(1, min(limit, 200))
    pids = await _visible_project_ids(db, user)

    q = select(Run, Project.display_name).join(Project, Project.id == Run.project_id)
    if pids is not None:
        if not pids:
            return {"items": [], "unread_count": 0}
        q = q.where(Run.project_id.in_(pids))
    q = q.order_by(Run.started_at.desc()).limit(limit)
    rows = (await db.execute(q)).all()

    run_ids = [r.Run.id for r in rows]
    finding_counts: dict[str, int] = {}
    if run_ids:
        fc = (await db.execute(
            select(RunEvent.run_id, func.count()).where(
                RunEvent.run_id.in_(run_ids), RunEvent.type == "finding.added"
            ).group_by(RunEvent.run_id))).all()
        finding_counts = dict(fc)

    items = []
    unread = 0
    for row in rows:
        run = row.Run
        attention = run.state in _ATTENTION
        live = run.state not in _TERMINAL
        if attention or live:
            unread += 1
        items.append({
            "kind": "run",
            "run_id": run.id,
            "project_id": run.project_id,
            "project": row.display_name,
            "state": run.state,
            "run_kind": run.kind,
            "target": run.target,
            "findings": finding_counts.get(run.id, 0),
            "attention": attention,
            "live": live,
            "ts": (run.updated_at or run.started_at).isoformat() if (run.updated_at or run.started_at) else None,
        })
    return {"items": items, "unread_count": unread}
