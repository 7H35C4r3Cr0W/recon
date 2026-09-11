"""Runs router — start a run (scope-checked + membership-checked), stream its persisted events,
cancel it. Live streaming is over the WebSocket (/ws/runs/{id}); this exposes REST start/status/
replay/cancel. Every project-scoped endpoint requires project membership; run-scoped endpoints
require membership of the run's project (closes the IDOR gaps)."""
from __future__ import annotations

import asyncio
import ipaddress
from datetime import UTC, datetime
from typing import Any

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
from nabu_agent.db.models import Checkpoint, Project, Run, ScopeTarget, User
from nabu_agent.db.session import get_db
from nabu_agent.engine.errors import ProjectNotFound, ScopeViolation
from nabu_agent.events.schema import NodeState, RunEventType
from nabu_agent.rbac import Perm
from nabu_agent.services import runs as runs_svc
from nabu_agent.settings import get_settings

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


# --- human-in-the-loop checkpoints ---------------------------------------------------------------
# Two gated flows share the Checkpoint table:
#   * kind="hosts" — the recon fan-out gate: a run parked in `awaiting_approval` resumes when a
#     member approves, or stops when rejected.
#   * kind in {spray, exploit} — the ATTACK gate (Phase A). An operator PROPOSES an executable
#     catalog action; a human APPROVES it behind the DOUBLE GATE (platform switch + per-project
#     toggle + this approval, plus exploit_confirmed / a chosen credential). Approval enqueues
#     execute_approved_action, which re-derives the command from the catalog and runs it through the
#     one gated door. The checkpoint stores only which action (service + action_id), never a command.
_HOST_KIND = "hosts"
_ATTACK_KINDS = {"spray", "exploit"}


class AttackProposalBody(BaseModel):
    kind: str                        # spray | exploit
    target: str                      # an in-scope host (re-validated at execute)
    service: str                     # the discovered service key (e.g. "smb", "http")
    action_id: str                   # the catalog action id — the ONLY thing that selects the command
    credential_ref: str | None = None  # a vault credential id — fills {user}/{password}/{hash}/{domain}
    params: dict[str, str] = {}      # operator-supplied fills for the remaining placeholders
    rationale: str = ""


class ApproveBody(BaseModel):
    exploit_confirmed: bool = False   # required for kind="exploit"
    credential_ref: str | None = None # required for kind="spray" (if not already on the proposal)


def _cp_view(cp: Checkpoint) -> dict[str, Any]:
    v: dict[str, Any] = {"id": cp.id, "run_id": cp.run_id, "kind": cp.kind, "status": cp.status,
         "target": cp.target, "action_id": cp.action_id, "rationale": cp.rationale,
         "approved_by": cp.approved_by,
         "approved_at": cp.approved_at.isoformat() if cp.approved_at else None}
    if cp.kind in _ATTACK_KINDS:
        v["service"] = (cp.requires or {}).get("service", "")
        v["credential_ref"] = cp.credential_ref
        v["exploit_confirmed"] = cp.exploit_confirmed
    return v


def _preview_command(project_id: str, target: str, service: str, action_id: str,
                     params: dict | None = None, credential_ref: str | None = None) -> str:
    """Open the target's profile and re-derive the exact shell line the catalog action resolves to,
    with the chosen credential + operator params applied — the SECRET is always redacted here (this
    feeds previews). Same server-side derivation the executor uses, so the preview is truthful and
    validates the action is attacker-runnable + fully filled. Raises ProjectNotFound / ValueError."""
    from nabu_agent.engine.creds_ref import resolve_credential
    from nabu_agent.engine.workspace import workspace_for
    from nabu_agent.services.runs import _resolve_gated_command

    prof = workspace_for(project_id, target).open()
    cred = resolve_credential(prof, credential_ref) if credential_ref else None
    if credential_ref and cred is None:
        raise ValueError("the chosen credential is not in the vault")
    return _resolve_gated_command(prof, service, action_id, params=params, credential=cred,
                                  redact_secret=True)


async def _enqueue_execute(cp_id: str) -> None:
    """Enqueue the approved attack onto the Arq worker (production) or run it in-process (dev/tests),
    mirroring the run driver's dispatch."""
    if get_settings().use_arq:
        pool = await bus.get_arq_pool()
        await pool.enqueue_job("execute_approved_action", cp_id, _job_id=f"attack:{cp_id}")
        return
    task = asyncio.create_task(runs_svc.execute_approved_action(cp_id))
    runs_svc._RUNNING.add(task)
    task.add_done_callback(runs_svc._RUNNING.discard)


@router.get("/runs/{run_id}/checkpoints")
async def list_checkpoints(db: AsyncSession = Depends(get_db),
                           run: Run = Depends(require_run_access)) -> dict:
    rows = (await db.execute(select(Checkpoint).where(Checkpoint.run_id == run.id)
                             .order_by(Checkpoint.id))).scalars().all()
    project = (await db.execute(select(Project).where(Project.id == run.project_id))).scalar_one_or_none()
    s = get_settings()
    views = []
    for c in rows:
        v = _cp_view(c)
        if c.kind in _ATTACK_KINDS:
            # a truthful, server-derived command preview + the live gate state (best-effort; a
            # missing/rebuilt profile just yields command=None, never a 500).
            try:
                v["command"] = await asyncio.to_thread(
                    _preview_command, run.project_id, c.target, v.get("service", ""), c.action_id,
                    (c.requires or {}).get("params") or {}, c.credential_ref)
            except Exception:
                v["command"] = None
            platform = (s.spray_enabled if c.kind == "spray" else s.exploit_enabled)
            proj = bool(project and (project.spray_enabled if c.kind == "spray" else project.exploit_enabled))
            v["gate"] = {"platform_enabled": platform, "project_enabled": proj,
                         "needs_exploit_confirm": c.kind == "exploit",
                         "needs_credential": c.kind == "spray"}
        views.append(v)
    return {"checkpoints": views}


@router.post("/runs/{run_id}/attack-proposals")
async def propose_attack(body: AttackProposalBody, db: AsyncSession = Depends(get_db),
                         user: User = Depends(get_current_user),
                         run: Run = Depends(require_run_perm(Perm.CHECKPOINT_DECIDE))) -> dict:
    """PROPOSE a spray/exploit action against a discovered service (operator+; viewers can't). This
    only creates a `proposed` checkpoint — it NEVER runs anything. Execution still needs the double
    gate at approve time. The action_id must resolve to an attacker-runnable, fully-filled command."""
    if body.kind not in _ATTACK_KINDS:
        raise HTTPException(status_code=422, detail="kind must be 'spray' or 'exploit'")
    scopes = [s.target for s in (await db.execute(
        select(ScopeTarget).where(ScopeTarget.project_id == run.project_id))).scalars().all()]
    if not _in_scope(body.target, scopes):
        raise ScopeViolation(f"{body.target} is outside the project scope")
    # per-run attack cap — bound how many gated actions one run can accumulate
    from nabu_agent.orchestration.limits import RunLimits
    n_attacks = len((await db.execute(select(Checkpoint).where(
        Checkpoint.run_id == run.id, Checkpoint.kind.in_(tuple(_ATTACK_KINDS))))).scalars().all())
    cap = RunLimits().max_gated_actions_per_run
    if n_attacks >= cap:
        raise HTTPException(status_code=409,
                            detail=f"attack cap reached ({cap} gated actions per run)")
    try:
        command = await asyncio.to_thread(
            _preview_command, run.project_id, body.target, body.service, body.action_id,
            body.params, body.credential_ref)
    except ProjectNotFound as exc:
        raise HTTPException(status_code=422,
                            detail="no recon profile for this target yet — run recon before proposing") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"action not proposable: {exc}") from exc

    cp = Checkpoint(run_id=run.id, kind=body.kind, status="proposed", target=body.target,
                    action_id=body.action_id, rationale=body.rationale or f"operator-proposed {body.kind}",
                    requires={"service": body.service, "params": dict(body.params)},
                    credential_ref=body.credential_ref)
    db.add(cp)
    await db.commit()
    node = f"attack-{cp.id}"
    await runs_svc.emit_event(run.id, RunEventType.CHECKPOINT_REQUESTED, {
        "node_id": node, "node_state": NodeState.STUCK.value, "checkpoint_id": cp.id,
        "kind": cp.kind, "target": cp.target, "action_id": cp.action_id, "attack": True})
    await runs_svc.emit_event(run.id, RunEventType.APPROVAL_REQUIRED, {
        "node_id": node, "node_state": NodeState.STUCK.value, "checkpoint_id": cp.id, "attack": True,
        "kind": cp.kind, "target": cp.target, "action_id": cp.action_id, "command": command,
        "message": f"{cp.kind} proposed against {cp.target} — approve (double gate) or reject."})
    await audit.record(actor_user_id=user.id, action=audit.ATTACK_PROPOSED, object_type="checkpoint",
                       object_id=cp.id, project_id=run.project_id,
                       details={"kind": cp.kind, "target": cp.target, "action_id": cp.action_id})
    return {"checkpoint_id": cp.id, "kind": cp.kind, "status": "proposed", "command": command}


async def _load_proposed(cp_id: str, run: Run, db: AsyncSession) -> Checkpoint:
    cp = (await db.execute(select(Checkpoint).where(
        Checkpoint.id == cp_id, Checkpoint.run_id == run.id))).scalar_one_or_none()
    if cp is None:
        raise HTTPException(status_code=404, detail="checkpoint not found")
    if cp.status != "proposed":
        raise HTTPException(status_code=409, detail=f"checkpoint already {cp.status}")
    return cp


@router.post("/runs/{run_id}/checkpoints/{cp_id}/approve")
async def approve_checkpoint(cp_id: str, body: ApproveBody = ApproveBody(),
                             db: AsyncSession = Depends(get_db),
                             user: User = Depends(get_current_user),
                             run: Run = Depends(require_run_perm(Perm.CHECKPOINT_DECIDE))) -> dict:
    cp = await _load_proposed(cp_id, run, db)

    if cp.kind in _ATTACK_KINDS:
        # DOUBLE GATE (RBAC already checked by the dependency).
        s = get_settings()
        platform = s.spray_enabled if cp.kind == "spray" else s.exploit_enabled
        if not platform:
            raise HTTPException(status_code=409,
                                detail=f"{cp.kind} is disabled platform-wide (set NABU_{cp.kind.upper()}_ENABLED)")
        project = (await db.execute(select(Project).where(Project.id == run.project_id))).scalar_one_or_none()
        proj_on = bool(project and (project.spray_enabled if cp.kind == "spray" else project.exploit_enabled))
        if not proj_on:
            raise HTTPException(status_code=409,
                                detail=f"enable {cp.kind} for this project first (project Settings)")
        if cp.kind == "exploit" and not body.exploit_confirmed:
            raise HTTPException(status_code=422, detail="exploit requires exploit_confirmed=true")
        cred = body.credential_ref or cp.credential_ref
        if cp.kind == "spray" and not cred:
            raise HTTPException(status_code=422, detail="spray requires a credential_ref")
        cp.status = "approved"
        cp.approved_by = user.id
        cp.approved_at = datetime.now(UTC)
        cp.exploit_confirmed = bool(body.exploit_confirmed) or cp.exploit_confirmed
        cp.credential_ref = cred
        await db.commit()
        await audit.record(actor_user_id=user.id, action=audit.CHECKPOINT_DECIDED, object_type="checkpoint",
                           object_id=cp.id, project_id=run.project_id,
                           details={"status": "approved", "kind": cp.kind, "target": cp.target})
        await _enqueue_execute(cp.id)
        return {"ok": True, "status": "approved", "checkpoint_id": cp.id, "enqueued": True}

    # kind == "hosts": the recon fan-out gate (the driver coroutine is polling for this flip).
    cp.status = "approved"
    cp.approved_by = user.id
    cp.approved_at = datetime.now(UTC)
    await db.commit()
    await audit.record(actor_user_id=user.id, action=audit.CHECKPOINT_DECIDED, object_type="checkpoint",
                       object_id=cp.id, project_id=run.project_id, details={"status": "approved", "kind": cp.kind})
    return {"ok": True, "status": "approved", "checkpoint_id": cp.id}


@router.post("/runs/{run_id}/checkpoints/{cp_id}/reject")
async def reject_checkpoint(cp_id: str, db: AsyncSession = Depends(get_db),
                            user: User = Depends(get_current_user),
                            run: Run = Depends(require_run_perm(Perm.CHECKPOINT_DECIDE))) -> dict:
    cp = await _load_proposed(cp_id, run, db)
    cp.status = "rejected"
    cp.approved_by = user.id
    cp.approved_at = datetime.now(UTC)
    await db.commit()
    await audit.record(actor_user_id=user.id, action=audit.CHECKPOINT_DECIDED, object_type="checkpoint",
                       object_id=cp.id, project_id=run.project_id, details={"status": "rejected", "kind": cp.kind})
    return {"ok": True, "status": "rejected", "checkpoint_id": cp.id}
