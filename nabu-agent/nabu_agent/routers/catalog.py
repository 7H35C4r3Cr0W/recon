"""Catalog router — DISPLAY-ONLY decision aids. The engine's catalog ranks/pre-fills command text
and executes NOTHING; even 'attacker'-runnable actions are surfaced with an ``executable`` flag but
are never auto-run (an attack only ever runs behind the separate human-gated checkpoint)."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent.auth.deps import get_current_user, require_project_member
from nabu_agent.db.models import ScopeTarget, User
from nabu_agent.db.session import get_db
from nabu_agent.engine import gateway
from nabu_agent.engine import tools as etools
from nabu_agent.engine.errors import ProjectNotFound

router = APIRouter(tags=["catalog"])


async def _scope_for(db: AsyncSession, project_id: str) -> str | None:
    rows = (await db.execute(select(ScopeTarget).where(ScopeTarget.project_id == project_id))).scalars().all()
    if not rows:
        return None
    return next((s.target for s in rows if s.is_entry), rows[0].target)


@router.get("/catalog/services/{key}")
async def service_catalog(key: str, _user: User = Depends(get_current_user)) -> dict:
    """The reference action catalog for a service key (e.g. ``smb``, ``http``) — stateless, needs no
    project. Any authenticated user; display-only."""
    return await asyncio.to_thread(etools.catalog_actions_for, key, {})


@router.get("/projects/{project_id}/catalog")
async def project_catalog(project_id: str, db: AsyncSession = Depends(get_db),
                          _auth: str = Depends(require_project_member)) -> dict:
    """The catalog for each service discovered in this project, ranked against its evidence."""
    scope = await _scope_for(db, project_id)
    if not scope:
        return {"services": []}
    try:
        svcs = await asyncio.to_thread(gateway.list_services, project_id, scope, None)
        findings = await asyncio.to_thread(gateway.list_findings, project_id, scope, None)
    except ProjectNotFound:
        return {"services": []}
    evidence = {
        "services": [[s.get("port"), s.get("service") or s.get("proto")] for s in svcs],
        "findings": findings,
        "values": {"target": scope},
    }
    seen: set[str] = set()
    out = []
    for s in svcs:
        name = s.get("service") or s.get("proto") or ""
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(await asyncio.to_thread(etools.catalog_actions_for, name, evidence))
    return {"services": out}


@router.get("/projects/{project_id}/suggestions")
async def project_suggestions(project_id: str, db: AsyncSession = Depends(get_db),
                              _auth: str = Depends(require_project_member)) -> dict:
    """Ranked next-step suggestions for the project (display-only; the engine's suggest_next_steps)."""
    scope = await _scope_for(db, project_id)
    if not scope:
        return {"next_steps": []}
    try:
        prof = await asyncio.to_thread(gateway.load_profile, project_id, scope, None)
        return await asyncio.to_thread(etools.suggest_next_steps, prof)
    except ProjectNotFound:
        return {"next_steps": []}
