"""Projects + scope router. Creating a project records it in Postgres and reserves an engine Profile
dir; the Profile itself is created lazily on the first run. Scope targets are validated with the
engine's own validator before insert. list_projects returns only the caller's projects; per-project
reads/writes require membership."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent import audit
from nabu_agent.auth.deps import (
    get_current_user,
    require_project_member,
    require_project_owner,
    require_project_perm,
)
from nabu_agent.db.models import (
    AgentTask,
    Artifact,
    Checkpoint,
    FindingIndex,
    Project,
    ProjectMember,
    Run,
    RunEvent,
    ScopeTarget,
    ServiceMirror,
    User,
)
from nabu_agent.db.session import get_db
from nabu_agent.engine.workspace import delete_project_workspace
from nabu_agent.rbac import Perm
from nabu_agent.settings import get_settings

router = APIRouter(tags=["projects"])


class ProjectBody(BaseModel):
    display_name: str
    slug: str | None = None


class ScopeBody(BaseModel):
    target: str
    is_entry: bool = False


def _slug(name: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in name.lower()).strip("-")[:80] or "project"


@router.post("/projects")
async def create_project(body: ProjectBody, db: AsyncSession = Depends(get_db),
                         user: User = Depends(get_current_user)) -> dict:
    slug = body.slug or _slug(body.display_name)
    if (await db.execute(select(Project).where(Project.slug == slug))).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="project slug already exists")
    proj = Project(slug=slug, display_name=body.display_name, owner_id=user.id,
                   engine_profile_dir=f"{get_settings().workspace}/{slug}")
    db.add(proj)
    await db.flush()
    db.add(ProjectMember(project_id=proj.id, user_id=user.id, role="owner"))
    await db.commit()
    await audit.record(actor_user_id=user.id, action=audit.PROJECT_CREATED, object_type="project",
                       object_id=proj.id, project_id=proj.id, details={"name": proj.display_name})
    return {"id": proj.id, "slug": proj.slug, "display_name": proj.display_name}


@router.get("/projects")
async def list_projects(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    """Only the caller's projects (owned or member); a global admin sees all."""
    if user.role == "admin":
        rows = (await db.execute(select(Project))).scalars().all()
    else:
        member_ids = select(ProjectMember.project_id).where(ProjectMember.user_id == user.id)
        rows = (await db.execute(select(Project).where(
            or_(Project.owner_id == user.id, Project.id.in_(member_ids))))).scalars().all()
    return {"projects": [{"id": p.id, "slug": p.slug, "display_name": p.display_name,
                          "status": p.status} for p in rows]}


@router.get("/projects/{project_id}")
async def get_project(project_id: str, db: AsyncSession = Depends(get_db),
                      _auth: str = Depends(require_project_member)) -> dict:
    p = (await db.execute(select(Project).where(Project.id == project_id))).scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="project not found")
    return {"id": p.id, "slug": p.slug, "display_name": p.display_name, "status": p.status,
            "spray_enabled": p.spray_enabled, "exploit_enabled": p.exploit_enabled}


@router.get("/projects/{project_id}/scope")
async def list_scope(project_id: str, db: AsyncSession = Depends(get_db),
                     _auth: str = Depends(require_project_member)) -> dict:
    rows = (await db.execute(select(ScopeTarget).where(ScopeTarget.project_id == project_id))).scalars().all()
    return {"scope": [{"id": s.id, "target": s.target, "kind": s.kind, "is_entry": s.is_entry} for s in rows]}


@router.post("/projects/{project_id}/scope")
async def add_scope(project_id: str, body: ScopeBody, db: AsyncSession = Depends(get_db),
                    user: User = Depends(get_current_user),
                    _auth: str = Depends(require_project_perm(Perm.SCOPE_EDIT))) -> dict:
    from oscprecon.models import validate_host_or_range  # engine validator (argv-injection guard)
    try:
        target = validate_host_or_range(body.target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid target: {exc}") from exc
    kind = "range" if "/" in target else "host"
    row = ScopeTarget(project_id=project_id, target=target, kind=kind, is_entry=body.is_entry,
                      source="manual", added_by=user.id)
    db.add(row)
    await db.commit()
    await audit.record(actor_user_id=user.id, action=audit.SCOPE_ADDED, object_type="scope",
                       object_id=row.id, project_id=project_id, details={"target": row.target})
    return {"id": row.id, "target": row.target, "kind": row.kind}


_TERMINAL = ("done", "partial", "failed", "cancelled")


@router.delete("/projects/{project_id}/scope/{target_id}")
async def remove_scope(project_id: str, target_id: str, db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user),
                       _auth: str = Depends(require_project_perm(Perm.SCOPE_EDIT))) -> dict:
    """Remove an authorized-scope target. Needs the SCOPE_EDIT capability (operator/owner)."""
    row = (await db.execute(select(ScopeTarget).where(
        ScopeTarget.id == target_id, ScopeTarget.project_id == project_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="scope target not found")
    target = row.target
    await db.execute(delete(ScopeTarget).where(
        ScopeTarget.id == target_id, ScopeTarget.project_id == project_id))
    await db.commit()
    await audit.record(actor_user_id=user.id, action=audit.SCOPE_REMOVED, object_type="scope",
                       object_id=target_id, project_id=project_id, details={"target": target})
    return {"removed": True, "target": target}


@router.delete("/projects/{project_id}")
async def delete_project(project_id: str, db: AsyncSession = Depends(get_db),
                         user: User = Depends(get_current_user),
                         _owner: str = Depends(require_project_owner)) -> dict:
    """Delete a project: refuse while a run is active, then remove all DB rows AND the on-disk
    workspace (its Profile folders). Owner-or-admin only."""
    active = (await db.execute(select(Run.id).where(
        Run.project_id == project_id, Run.state.notin_(_TERMINAL)).limit(1))).scalar_one_or_none()
    if active is not None:
        raise HTTPException(status_code=409, detail="cancel the active run before deleting the project")

    run_ids = (await db.execute(select(Run.id).where(Run.project_id == project_id))).scalars().all()
    if run_ids:
        await db.execute(delete(RunEvent).where(RunEvent.run_id.in_(run_ids)))
        await db.execute(delete(Checkpoint).where(Checkpoint.run_id.in_(run_ids)))
        await db.execute(delete(AgentTask).where(AgentTask.run_id.in_(run_ids)))
    await db.execute(delete(Run).where(Run.project_id == project_id))
    await db.execute(delete(FindingIndex).where(FindingIndex.project_id == project_id))
    await db.execute(delete(ServiceMirror).where(ServiceMirror.project_id == project_id))
    await db.execute(delete(Artifact).where(Artifact.project_id == project_id))
    await db.execute(delete(ScopeTarget).where(ScopeTarget.project_id == project_id))
    await db.execute(delete(ProjectMember).where(ProjectMember.project_id == project_id))
    await db.execute(delete(Project).where(Project.id == project_id))
    await db.commit()

    # remove the on-disk workspace (Profile folders); confined to the workspace root
    ws = delete_project_workspace(project_id)
    await audit.record(actor_user_id=user.id, action=audit.PROJECT_DELETED, object_type="project",
                       object_id=project_id, project_id=project_id, details={"runs_removed": len(run_ids)})
    return {"deleted": True, "runs_removed": len(run_ids), "workspace": ws}


class MemberBody(BaseModel):
    email: str
    role: str = "viewer"   # owner | operator | viewer (per-project)


@router.get("/projects/{project_id}/members")
async def list_members(project_id: str, db: AsyncSession = Depends(get_db),
                       _auth: str = Depends(require_project_member)) -> dict:
    """The project team: the owner plus explicit members. Any member may view it."""
    proj = (await db.execute(select(Project).where(Project.id == project_id))).scalar_one_or_none()
    rows = (await db.execute(select(ProjectMember).where(
        ProjectMember.project_id == project_id))).scalars().all()
    ids = {proj.owner_id} | {r.user_id for r in rows} if proj else {r.user_id for r in rows}
    users = {u.id: u for u in (await db.execute(select(User).where(User.id.in_(ids)))).scalars().all()}
    out: list[dict[str, str | None]] = []
    if proj and proj.owner_id in users:
        out.append({"user_id": proj.owner_id, "email": users[proj.owner_id].email, "role": "owner"})
    for r in rows:
        if proj and r.user_id == proj.owner_id:
            continue  # the owner's power comes from ownership, not a member row
        out.append({"user_id": r.user_id, "email": users[r.user_id].email if r.user_id in users else None,
                    "role": r.role})
    return {"members": out}


@router.post("/projects/{project_id}/members")
async def add_member(project_id: str, body: MemberBody, db: AsyncSession = Depends(get_db),
                     user: User = Depends(get_current_user),
                     _owner: str = Depends(require_project_owner)) -> dict:
    """Add or re-role a project member (owner/admin only). The role gates capabilities via rbac."""
    if body.role not in ("owner", "operator", "viewer"):
        raise HTTPException(status_code=422, detail="role must be owner, operator, or viewer")
    target = (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="no user with that email")
    m = (await db.execute(select(ProjectMember).where(
        ProjectMember.project_id == project_id, ProjectMember.user_id == target.id))).scalar_one_or_none()
    if m is None:
        db.add(ProjectMember(project_id=project_id, user_id=target.id, role=body.role))
    else:
        m.role = body.role
    await db.commit()
    await audit.record(actor_user_id=user.id, action=audit.MEMBER_CHANGED, object_type="member",
                       object_id=target.id, project_id=project_id,
                       details={"email": target.email, "role": body.role})
    return {"user_id": target.id, "email": target.email, "role": body.role}


@router.delete("/projects/{project_id}/members/{user_id}")
async def remove_member(project_id: str, user_id: str, db: AsyncSession = Depends(get_db),
                        user: User = Depends(get_current_user),
                        _owner: str = Depends(require_project_owner)) -> dict:
    """Remove a project member (owner/admin only). The owner cannot be removed this way."""
    proj = (await db.execute(select(Project).where(Project.id == project_id))).scalar_one_or_none()
    if proj and proj.owner_id == user_id:
        raise HTTPException(status_code=409, detail="the project owner cannot be removed")
    await db.execute(delete(ProjectMember).where(
        ProjectMember.project_id == project_id, ProjectMember.user_id == user_id))
    await db.commit()
    await audit.record(actor_user_id=user.id, action=audit.MEMBER_CHANGED, object_type="member",
                       object_id=user_id, project_id=project_id, details={"removed": True})
    return {"removed": True}


class SettingsBody(BaseModel):
    scan_profile: str | None = None
    spray_enabled: bool | None = None
    exploit_enabled: bool | None = None
    status: str | None = None


@router.get("/projects/{project_id}/settings")
async def get_project_settings(project_id: str, db: AsyncSession = Depends(get_db),
                               _auth: str = Depends(require_project_member)) -> dict:
    """The project's scan profile + attack gates + status. Any member may read it."""
    p = (await db.execute(select(Project).where(Project.id == project_id))).scalar_one_or_none()
    if p is None:
        raise HTTPException(status_code=404, detail="project not found")
    return {"scan_profile": p.scan_profile, "spray_enabled": p.spray_enabled,
            "exploit_enabled": p.exploit_enabled, "status": p.status}


@router.patch("/projects/{project_id}/settings")
async def update_project_settings(project_id: str, body: SettingsBody, db: AsyncSession = Depends(get_db),
                                  user: User = Depends(get_current_user),
                                  _auth: str = Depends(require_project_perm(Perm.SETTINGS_EDIT))) -> dict:
    """Update scan profile / attack gates / status. SETTINGS_EDIT = owner/admin only — flipping the
    spray or exploit gate is an owner decision (and is still only ONE of the two locks: an attack
    also needs a per-action human-approved checkpoint)."""
    p = (await db.execute(select(Project).where(Project.id == project_id))).scalar_one_or_none()
    if p is None:
        raise HTTPException(status_code=404, detail="project not found")
    changed: dict = {}
    if body.scan_profile is not None:
        if body.scan_profile not in ("quick", "default", "exam", "full"):
            raise HTTPException(status_code=422, detail="scan_profile must be quick|default|exam|full")
        p.scan_profile = body.scan_profile
        changed["scan_profile"] = body.scan_profile
    if body.spray_enabled is not None:
        p.spray_enabled = body.spray_enabled
        changed["spray_enabled"] = body.spray_enabled
    if body.exploit_enabled is not None:
        p.exploit_enabled = body.exploit_enabled
        changed["exploit_enabled"] = body.exploit_enabled
    if body.status is not None:
        if body.status not in ("active", "archived"):
            raise HTTPException(status_code=422, detail="status must be active|archived")
        p.status = body.status
        changed["status"] = body.status
    await db.commit()
    if changed:
        await audit.record(actor_user_id=user.id, action=audit.SETTINGS_CHANGED, object_type="project",
                           object_id=project_id, project_id=project_id, details=changed)
    return {"scan_profile": p.scan_profile, "spray_enabled": p.spray_enabled,
            "exploit_enabled": p.exploit_enabled, "status": p.status}
