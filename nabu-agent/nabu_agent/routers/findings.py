"""Findings / services / graph — read-only views over the project's engine Profile via the gateway.

A project's recon truth lives in its on-disk oscprecon Profile (created by the first REAL run). For a
project with no Profile yet (e.g. demo-only), these return empty rather than 404, so the UI stays
calm. The (blocking) engine reads run in a threadpool.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent.auth.deps import get_current_user
from nabu_agent.db.models import ScopeTarget, User
from nabu_agent.db.session import get_db
from nabu_agent.engine import gateway
from nabu_agent.engine.errors import ProjectNotFound

router = APIRouter(tags=["findings"])


async def _scope_for(db: AsyncSession, project_id: str) -> str | None:
    """The project's entry scope target (the Profile's target); None if no scope defined yet."""
    rows = (await db.execute(select(ScopeTarget).where(ScopeTarget.project_id == project_id))).scalars().all()
    if not rows:
        return None
    entry = next((s for s in rows if s.is_entry), rows[0])
    return entry.target


@router.get("/projects/{project_id}/findings")
async def get_findings(project_id: str, db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user)) -> dict:
    scope = await _scope_for(db, project_id)
    if not scope:
        return {"findings": []}
    try:
        rows = await asyncio.to_thread(gateway.list_findings, project_id, scope, None)
    except ProjectNotFound:
        return {"findings": []}
    return {"findings": rows}


@router.get("/projects/{project_id}/services")
async def get_services(project_id: str, db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user)) -> dict:
    scope = await _scope_for(db, project_id)
    if not scope:
        return {"services": []}
    try:
        rows = await asyncio.to_thread(gateway.list_services, project_id, scope, None)
    except ProjectNotFound:
        return {"services": []}
    return {"services": rows}


@router.get("/projects/{project_id}/graph")
async def get_graph(project_id: str, db: AsyncSession = Depends(get_db),
                    user: User = Depends(get_current_user)) -> dict:
    scope = await _scope_for(db, project_id)
    if not scope:
        return {"nodes": [], "edges": []}
    try:
        return await asyncio.to_thread(gateway.build_graph, project_id, scope, None)
    except ProjectNotFound:
        return {"nodes": [], "edges": []}
