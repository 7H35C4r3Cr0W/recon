"""Runs router — start a run (scope-checked + membership-checked), stream its persisted events,
cancel it. Live streaming is over the WebSocket (/ws/runs/{id}); this exposes REST start/status/
replay/cancel. Every project-scoped endpoint requires project membership; run-scoped endpoints
require membership of the run's project (closes the IDOR gaps)."""
from __future__ import annotations

import ipaddress
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent import audit, bus
from nabu_agent.auth.deps import (
    get_current_user,
    require_project_member,
    require_project_perm,
    require_run_access,
    require_run_perm,
)
from nabu_agent.db.models import Checkpoint, Run, ScopeTarget, User
from nabu_agent.db.session import get_db
from nabu_agent.engine.errors import ScopeViolation
from nabu_agent.rbac import Perm
from nabu_agent.services import runs as runs_svc

router = APIRouter(tags=["runs"])


class RunBody(BaseModel):
    target: str
    kind: str = "demo"   # demo | scan | agent


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
                    user: User = Depends(get_current_user),
                    _auth: str = Depends(require_project_perm(Perm.RUN_START))) -> dict:
    scopes = [s.target for s in (await db.execute(
        select(ScopeTarget).where(ScopeTarget.project_id == project_id))).scalars().all()]
    if not scopes:
        raise HTTPException(status_code=422, detail="add an authorized scope target before starting a run")
    if not _in_scope(body.target, scopes):
        # the authorized-scope-only gate — ScopeViolation is mapped to 403 + the typed error envelope
        raise ScopeViolation(f"{body.target} is outside the project scope")
    run = Run(project_id=project_id, kind=body.kind, target=body.target, state="queued",
              requested_by=user.id, heartbeat_at=datetime.now(UTC))
    db.add(run)
    await db.commit()
    try:
        await runs_svc.start(run.id, body.target, body.kind, project_id=project_id)
    except Exception as exc:  # enqueue failed (e.g. worker/redis down) — don't leave it stuck 'queued'
        run.state = "failed"
        run.error = f"failed to start: {exc}"
        await db.commit()
        raise HTTPException(status_code=503, detail="could not start run (worker/queue unavailable)") from exc
    await audit.record(actor_user_id=user.id, action=audit.RUN_STARTED, object_type="run",
                       object_id=run.id, project_id=project_id,
                       details={"target": body.target, "kind": body.kind})
    return {"run_id": run.id, "state": "queued", "target": body.target, "kind": body.kind}


@router.get("/projects/{project_id}/runs")
async def list_runs(project_id: str, db: AsyncSession = Depends(get_db),
                    _auth: str = Depends(require_project_member)) -> dict:
    stmt = select(Run).where(Run.project_id == project_id).order_by(Run.started_at.desc())
    rows = (await db.execute(stmt)).scalars().all()
    return {"runs": [{"id": r.id, "state": r.state, "target": r.target, "kind": r.kind} for r in rows]}


@router.get("/runs/{run_id}")
async def get_run(run: Run = Depends(require_run_access)) -> dict:
    return {"id": run.id, "state": run.state, "target": run.target, "kind": run.kind,
            "project_id": run.project_id}


@router.get("/runs/{run_id}/events")
async def run_events(after: int = 0, db: AsyncSession = Depends(get_db),
                     run: Run = Depends(require_run_access)) -> dict:
    return {"events": await runs_svc.replay_events(db, run.id, after)}


@router.post("/runs/{run_id}/cancel")
async def cancel_run(db: AsyncSession = Depends(get_db),
                     user: User = Depends(get_current_user),
                     run: Run = Depends(require_run_perm(Perm.RUN_CANCEL))) -> dict:
    await bus.request_cancel(run.id)
    if run.state not in {"done", "failed", "cancelled", "partial"}:
        run.cancel_requested = True
        await db.commit()
    await audit.record(actor_user_id=user.id, action=audit.RUN_CANCELLED, object_type="run",
                       object_id=run.id, project_id=run.project_id)
    return {"ok": True}


# --- human-in-the-loop checkpoints (the host-count fan-out gate) ---------------------------------
# A run parked in `awaiting_approval` has a `proposed` Checkpoint; a project member approves it to
# resume the fan-out, or rejects it to stop the run before it spends the fan-out. (Spray/exploit
# checkpoints are proposal-only for now — their execution gate is a later phase.)
_APPROVABLE_KINDS = {"hosts"}


def _cp_view(cp: Checkpoint) -> dict:
    return {"id": cp.id, "run_id": cp.run_id, "kind": cp.kind, "status": cp.status,
            "target": cp.target, "action_id": cp.action_id, "rationale": cp.rationale,
            "approved_by": cp.approved_by,
            "approved_at": cp.approved_at.isoformat() if cp.approved_at else None}


@router.get("/runs/{run_id}/checkpoints")
async def list_checkpoints(db: AsyncSession = Depends(get_db),
                           run: Run = Depends(require_run_access)) -> dict:
    rows = (await db.execute(select(Checkpoint).where(Checkpoint.run_id == run.id)
                             .order_by(Checkpoint.id))).scalars().all()
    return {"checkpoints": [_cp_view(c) for c in rows]}


async def _decide_checkpoint(cp_id: str, run: Run, user: User, db: AsyncSession, status: str) -> dict:
    cp = (await db.execute(select(Checkpoint).where(
        Checkpoint.id == cp_id, Checkpoint.run_id == run.id))).scalar_one_or_none()
    if cp is None:
        raise HTTPException(status_code=404, detail="checkpoint not found")
    if cp.kind not in _APPROVABLE_KINDS:
        # spray/exploit approval is gated separately (spray_enabled / per-action confirm) — not here
        raise HTTPException(status_code=409, detail=f"checkpoint kind '{cp.kind}' is not approvable here")
    if cp.status != "proposed":
        raise HTTPException(status_code=409, detail=f"checkpoint already {cp.status}")
    cp.status = status
    cp.approved_by = user.id
    cp.approved_at = datetime.now(UTC)
    await db.commit()
    await audit.record(actor_user_id=user.id, action=audit.CHECKPOINT_DECIDED, object_type="checkpoint",
                       object_id=cp.id, project_id=run.project_id,
                       details={"status": status, "kind": cp.kind})
    return {"ok": True, "status": status, "checkpoint_id": cp.id}


@router.post("/runs/{run_id}/checkpoints/{cp_id}/approve")
async def approve_checkpoint(cp_id: str, db: AsyncSession = Depends(get_db),
                             user: User = Depends(get_current_user),
                             run: Run = Depends(require_run_perm(Perm.CHECKPOINT_DECIDE))) -> dict:
    return await _decide_checkpoint(cp_id, run, user, db, "approved")


@router.post("/runs/{run_id}/checkpoints/{cp_id}/reject")
async def reject_checkpoint(cp_id: str, db: AsyncSession = Depends(get_db),
                            user: User = Depends(get_current_user),
                            run: Run = Depends(require_run_perm(Perm.CHECKPOINT_DECIDE))) -> dict:
    return await _decide_checkpoint(cp_id, run, user, db, "rejected")
