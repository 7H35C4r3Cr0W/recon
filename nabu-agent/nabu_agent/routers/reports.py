"""Reports / artifacts — the clean report markdown (read-only render) + artifact listing."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent.auth.deps import get_current_user, require_project_member
from nabu_agent.db.models import Artifact, ScopeTarget, User
from nabu_agent.db.session import get_db
from nabu_agent.engine import gateway
from nabu_agent.engine.errors import ProjectNotFound

router = APIRouter(tags=["reports"])


async def _scope_for(db: AsyncSession, project_id: str) -> str | None:
    rows = (await db.execute(select(ScopeTarget).where(ScopeTarget.project_id == project_id))).scalars().all()
    if not rows:
        return None
    entry = next((s for s in rows if s.is_entry), rows[0])
    return entry.target


@router.get("/projects/{project_id}/report")
async def get_report(project_id: str, db: AsyncSession = Depends(get_db),
                     user: User = Depends(get_current_user),
                     _auth: str = Depends(require_project_member)) -> dict:
    scope = await _scope_for(db, project_id)
    if not scope:
        return {"markdown": "_No recon has run yet — start a run to generate a report._"}
    try:
        # A CIDR/range scope fans out per host, so aggregate every per-host Profile into one
        # combined report + next steps; a single host renders its own report directly.
        if "/" in scope:
            markdown = await asyncio.to_thread(gateway.render_combined_report, project_id)
        else:
            markdown = await asyncio.to_thread(gateway.render_report, project_id, scope, None)
    except ProjectNotFound:
        return {"markdown": "_No report yet — the first run will create the project workspace._"}
    return {"markdown": markdown}


@router.post("/projects/{project_id}/report")
async def render_report(project_id: str, db: AsyncSession = Depends(get_db),
                        user: User = Depends(get_current_user),
                     _auth: str = Depends(require_project_member)) -> dict:
    # MVP: re-render on demand (the worker persists report.md during a real run via generate_report).
    return await get_report(project_id, db, user)


@router.get("/projects/{project_id}/artifacts")
async def list_artifacts(project_id: str, db: AsyncSession = Depends(get_db),
                         user: User = Depends(get_current_user),
                     _auth: str = Depends(require_project_member)) -> dict:
    rows = (await db.execute(select(Artifact).where(Artifact.project_id == project_id))).scalars().all()
    return {"artifacts": [{"id": a.id, "kind": a.kind, "filename": a.filename,
                           "content_type": a.content_type, "size_bytes": a.size_bytes} for a in rows]}


@router.post("/projects/{project_id}/export")
async def export_project(project_id: str, user: User = Depends(get_current_user),
                     _auth: str = Depends(require_project_member)) -> dict:
    raise HTTPException(status_code=501, detail="project export wired in a later phase")
