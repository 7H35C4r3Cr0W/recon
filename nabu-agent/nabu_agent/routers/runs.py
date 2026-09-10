"""Runs router — start a run (scope-checked), stream its persisted events, cancel it. Live streaming
is over the WebSocket (/ws/runs/{id}); this exposes REST start/status/replay/cancel."""
from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent import bus
from nabu_agent.auth.deps import get_current_user
from nabu_agent.db.models import Run, ScopeTarget, User
from nabu_agent.db.session import get_db
from nabu_agent.services import runs as runs_svc

router = APIRouter(tags=["runs"])


class RunBody(BaseModel):
    target: str
    kind: str = "demo"   # demo | scan (real recon wired next)


def _in_scope(target: str, scopes: list[str]) -> bool:
    for s in scopes:
        if target == s:
            return True
        try:
            if ipaddress.ip_address(target) in ipaddress.ip_network(s, strict=False):
                return True
        except ValueError:
            continue
    return False


@router.post("/projects/{project_id}/runs")
async def start_run(project_id: str, body: RunBody, db: AsyncSession = Depends(get_db),
                    user: User = Depends(get_current_user)) -> dict:
    scopes = [s.target for s in (await db.execute(
        select(ScopeTarget).where(ScopeTarget.project_id == project_id))).scalars().all()]
    if not scopes:
        raise HTTPException(status_code=422, detail="add an authorized scope target first")
    if not _in_scope(body.target, scopes):
        # the authorized-scope-only gate — mirrors the engine's scope-lock
        raise HTTPException(status_code=403, detail={"code": "scope_violation",
                            "message": f"{body.target} is outside the project scope"})
    run = Run(project_id=project_id, kind=body.kind, target=body.target, state="queued",
              requested_by=user.id)
    db.add(run)
    await db.commit()
    runs_svc.launch(run.id, body.target, body.kind, project_id=project_id)
    return {"run_id": run.id, "state": "queued", "target": body.target, "kind": body.kind}


@router.get("/projects/{project_id}/runs")
async def list_runs(project_id: str, db: AsyncSession = Depends(get_db),
                    user: User = Depends(get_current_user)) -> dict:
    stmt = select(Run).where(Run.project_id == project_id).order_by(Run.started_at.desc())
    rows = (await db.execute(stmt)).scalars().all()
    return {"runs": [{"id": r.id, "state": r.state, "target": r.target, "kind": r.kind} for r in rows]}


@router.get("/runs/{run_id}")
async def get_run(run_id: str, db: AsyncSession = Depends(get_db),
                  user: User = Depends(get_current_user)) -> dict:
    r = (await db.execute(select(Run).where(Run.id == run_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(status_code=404, detail="run not found")
    return {"id": r.id, "state": r.state, "target": r.target, "kind": r.kind, "project_id": r.project_id}


@router.get("/runs/{run_id}/events")
async def run_events(run_id: str, after: int = 0, db: AsyncSession = Depends(get_db),
                     user: User = Depends(get_current_user)) -> dict:
    return {"events": await runs_svc.replay_events(db, run_id, after)}


@router.post("/runs/{run_id}/cancel")
async def cancel_run(run_id: str, db: AsyncSession = Depends(get_db),
                     user: User = Depends(get_current_user)) -> dict:
    await bus.request_cancel(run_id)
    r = (await db.execute(select(Run).where(Run.id == run_id))).scalar_one_or_none()
    if r and r.state not in {"done", "failed", "cancelled", "partial"}:
        r.cancel_requested = True
        await db.commit()
    return {"ok": True}
