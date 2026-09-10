"""Audit router — read the platform activity trail (WHO did WHAT). The per-project view is
membership-gated; the global view is admin-only. Rows are written by ``nabu_agent.audit.record``."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent.auth.deps import require_admin, require_project_member
from nabu_agent.db.models import AuditLog, User
from nabu_agent.db.session import get_db

router = APIRouter(tags=["audit"])


def _view(rows: list[AuditLog]) -> list[dict]:
    return [{"ts": r.ts.isoformat() if r.ts else None, "actor_user_id": r.actor_user_id,
             "action": r.action, "result": r.result, "object_type": r.object_type,
             "object_id": r.object_id, "project_id": r.project_id, "details": r.details}
            for r in rows]


@router.get("/projects/{project_id}/activity")
async def project_activity(project_id: str, limit: int = 100, db: AsyncSession = Depends(get_db),
                           _auth: str = Depends(require_project_member)) -> dict:
    """The activity trail for one project (newest first). Any project member may read it."""
    limit = max(1, min(limit, 500))
    rows = (await db.execute(select(AuditLog).where(AuditLog.project_id == project_id)
                             .order_by(AuditLog.ts.desc(), AuditLog.id.desc()).limit(limit))).scalars().all()
    return {"activity": _view(list(rows))}


@router.get("/audit")
async def global_audit(limit: int = 200, action: str | None = None,
                       db: AsyncSession = Depends(get_db),
                       _admin: User = Depends(require_admin)) -> dict:
    """The whole platform trail (newest first) — admin only. Optional ``action`` slug filter."""
    limit = max(1, min(limit, 1000))
    stmt = select(AuditLog).order_by(AuditLog.ts.desc(), AuditLog.id.desc()).limit(limit)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    rows = (await db.execute(stmt)).scalars().all()
    return {"audit": _view(list(rows))}
