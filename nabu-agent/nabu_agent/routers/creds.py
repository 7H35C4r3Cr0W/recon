"""Credentials vault. The secret VALUE is never returned by the API — list/add responses carry only
metadata (username, type, domain, source, where it's been tested). Operator+ only (CREDS_VIEW).
Creds live in the per-project engine Profile (creds.json)."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent.auth.deps import require_project_perm
from nabu_agent.db.models import ScopeTarget
from nabu_agent.db.session import get_db
from nabu_agent.engine import gateway
from nabu_agent.engine.errors import ProjectNotFound
from nabu_agent.rbac import Perm

router = APIRouter(tags=["creds"])


class CredBody(BaseModel):
    username: str
    secret: str
    secret_type: str = "password"
    domain: str = ""
    source: str = "manual"


async def _scope_for(db: AsyncSession, project_id: str) -> str | None:
    rows = (await db.execute(select(ScopeTarget).where(ScopeTarget.project_id == project_id))).scalars().all()
    if not rows:
        return None
    return next((s.target for s in rows if s.is_entry), rows[0].target)


def _cid(c) -> str:
    """Opaque stable id from the engine's credential identity key (never the plaintext alone).
    Delegates to the shared helper so the attack-gate resolver maps the same id back to this cred."""
    from nabu_agent.engine.creds_ref import credential_cid
    return credential_cid(c)


def _view(c) -> dict:
    # the secret VALUE is deliberately omitted — the API never returns it
    return {"id": _cid(c), "username": c.username, "secret_type": c.secret_type,
            "domain": c.domain, "source": c.source, "tested_against": list(c.tested_against)}


@router.get("/projects/{project_id}/credentials")
async def list_credentials(project_id: str, db: AsyncSession = Depends(get_db),
                           _auth: str = Depends(require_project_perm(Perm.CREDS_VIEW))) -> dict:
    scope = await _scope_for(db, project_id)
    if not scope:
        return {"credentials": []}
    try:
        prof = await asyncio.to_thread(gateway.load_profile, project_id, scope, None)
    except ProjectNotFound:
        return {"credentials": []}
    return {"credentials": [_view(c) for c in prof.credentials()]}


@router.post("/projects/{project_id}/credentials")
async def add_credential(project_id: str, body: CredBody, db: AsyncSession = Depends(get_db),
                         _auth: str = Depends(require_project_perm(Perm.CREDS_VIEW))) -> dict:
    if not body.username or not body.secret:
        raise HTTPException(status_code=422, detail="username and secret are required")
    scope = await _scope_for(db, project_id)
    if not scope:
        raise HTTPException(status_code=422, detail="add a scope target before storing credentials")
    from oscprecon.models import Credential

    from nabu_agent.engine.workspace import workspace_for

    def _add():
        prof = workspace_for(project_id, scope).open_or_create()
        cred = Credential(username=body.username, secret=body.secret, secret_type=body.secret_type,
                          domain=body.domain, source=body.source)
        prof.add_credential(cred)
        return cred
    cred = await asyncio.to_thread(_add)
    return _view(cred)


@router.delete("/projects/{project_id}/credentials/{cred_id}")
async def delete_credential(project_id: str, cred_id: str, db: AsyncSession = Depends(get_db),
                            _auth: str = Depends(require_project_perm(Perm.CREDS_VIEW))) -> dict:
    scope = await _scope_for(db, project_id)
    if not scope:
        raise HTTPException(status_code=404, detail="credential not found")
    try:
        prof = await asyncio.to_thread(gateway.load_profile, project_id, scope, None)
    except ProjectNotFound:
        raise HTTPException(status_code=404, detail="credential not found") from None
    match = next((c for c in prof.credentials() if _cid(c) == cred_id), None)
    if match is None:
        raise HTTPException(status_code=404, detail="credential not found")
    await asyncio.to_thread(prof.delete_credential, match)
    return {"removed": True}
