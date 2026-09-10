"""Findings / services / graph — read-only views over the project's engine Profile via the gateway.

A project's recon truth lives in its on-disk oscprecon Profile (created by the first REAL run). For a
project with no Profile yet (e.g. demo-only), these return empty rather than 404, so the UI stays
calm. The (blocking) engine reads run in a threadpool.
"""
from __future__ import annotations

import asyncio
import hashlib

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent import audit
from nabu_agent.auth.deps import get_current_user, require_project_member, require_project_perm
from nabu_agent.db.models import FindingTriage, ScopeTarget, User
from nabu_agent.db.session import get_db
from nabu_agent.engine import gateway
from nabu_agent.engine.errors import ProjectNotFound
from nabu_agent.rbac import Perm

router = APIRouter(tags=["findings"])

_TRIAGE_STATUSES = ("open", "reviewed", "confirmed", "dismissed")


def _finding_key(f: dict) -> str:
    """Stable id for a finding across re-runs: hash of host|port|kind|value."""
    raw = f"{f.get('_host', '')}|{f.get('port', '')}|{f.get('kind', '')}|{f.get('value', '')}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


async def _scope_for(db: AsyncSession, project_id: str) -> str | None:
    """The project's entry scope target (the Profile's target); None if no scope defined yet."""
    rows = (await db.execute(select(ScopeTarget).where(ScopeTarget.project_id == project_id))).scalars().all()
    if not rows:
        return None
    entry = next((s for s in rows if s.is_entry), rows[0])
    return entry.target


async def _merge_triage(db: AsyncSession, project_id: str, rows: list[dict]) -> list[dict]:
    """Tag each finding with a stable ``id`` and its operator ``triage`` (status + note)."""
    for f in rows:
        f["id"] = _finding_key(f)
    keys = [f["id"] for f in rows]
    tri = {t.finding_key: t for t in (await db.execute(select(FindingTriage).where(
        FindingTriage.project_id == project_id, FindingTriage.finding_key.in_(keys)))).scalars().all()}
    for f in rows:
        t = tri.get(f["id"])
        f["triage"] = {"status": t.status if t else "open", "note": t.note if t else ""}
    return rows


class TriageBody(BaseModel):
    status: str = "reviewed"
    note: str = ""


@router.get("/projects/{project_id}/findings")
async def get_findings(project_id: str, db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user),
                     _auth: str = Depends(require_project_member)) -> dict:
    scope = await _scope_for(db, project_id)
    if not scope:
        return {"findings": []}
    try:
        # a CIDR scope fans out per host — aggregate every per-host Profile's findings, not just the
        # (near-empty) sweep Profile; a single host reads its own findings.json directly.
        if "/" in scope:
            rows = await asyncio.to_thread(gateway.list_combined_findings, project_id)
        else:
            rows = await asyncio.to_thread(gateway.list_findings, project_id, scope, None)
    except ProjectNotFound:
        return {"findings": []}
    return {"findings": await _merge_triage(db, project_id, rows)}


@router.post("/projects/{project_id}/findings/{finding_id}/triage")
async def set_triage(project_id: str, finding_id: str, body: TriageBody,
                     db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
                     _auth: str = Depends(require_project_perm(Perm.RUN_START))) -> dict:
    """Set a finding's triage status + note (operator+; viewers can't triage). Findings themselves
    are immutable engine truth — this is an overlay keyed by the finding's stable id."""
    if body.status not in _TRIAGE_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {_TRIAGE_STATUSES}")
    from datetime import UTC, datetime
    row = (await db.execute(select(FindingTriage).where(
        FindingTriage.project_id == project_id, FindingTriage.finding_key == finding_id))).scalar_one_or_none()
    if row is None:
        row = FindingTriage(project_id=project_id, finding_key=finding_id)
        db.add(row)
    row.status = body.status
    row.note = body.note
    row.updated_by = user.id
    row.updated_at = datetime.now(UTC)
    await db.commit()
    await audit.record(actor_user_id=user.id, action=audit.FINDING_TRIAGED, object_type="finding",
                       object_id=finding_id, project_id=project_id,
                       details={"triage": body.status})
    return {"id": finding_id, "status": row.status, "note": row.note}


@router.get("/projects/{project_id}/services")
async def get_services(project_id: str, db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user),
                     _auth: str = Depends(require_project_member)) -> dict:
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
                    user: User = Depends(get_current_user),
                     _auth: str = Depends(require_project_member)) -> dict:
    scope = await _scope_for(db, project_id)
    if not scope:
        return {"nodes": [], "edges": []}
    try:
        return await asyncio.to_thread(gateway.build_graph, project_id, scope, None)
    except ProjectNotFound:
        return {"nodes": [], "edges": []}
