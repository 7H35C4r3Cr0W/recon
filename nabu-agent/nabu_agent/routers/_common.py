"""Small shared helpers for the read-only project routers (kept in one place so scope resolution
can't drift between findings / catalog / creds / reports)."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent.db.models import ScopeTarget


async def entry_scope(db: AsyncSession, project_id: str) -> str | None:
    """The project's entry scope target (the engine Profile's target); None if no scope defined yet."""
    rows = (await db.execute(select(ScopeTarget).where(ScopeTarget.project_id == project_id))).scalars().all()
    if not rows:
        return None
    return next((s.target for s in rows if getattr(s, "is_entry", False)), rows[0].target)
