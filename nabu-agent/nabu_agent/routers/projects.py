"""Projects + scope router. Creating a project records it in Postgres and reserves an engine Profile
dir; the Profile itself is created lazily on the first real run. Scope targets are validated with the
engine's own validator before insert (the authorized-scope allowlist)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent.auth.deps import get_current_user
from nabu_agent.db.models import Project, ProjectMember, ScopeTarget, User
from nabu_agent.db.session import get_db
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
    return {"id": proj.id, "slug": proj.slug, "display_name": proj.display_name}


@router.get("/projects")
async def list_projects(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    rows = (await db.execute(select(Project))).scalars().all()
    return {"projects": [{"id": p.id, "slug": p.slug, "display_name": p.display_name,
                          "status": p.status} for p in rows]}


@router.get("/projects/{project_id}")
async def get_project(project_id: str, db: AsyncSession = Depends(get_db),
                      user: User = Depends(get_current_user)) -> dict:
    p = (await db.execute(select(Project).where(Project.id == project_id))).scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="project not found")
    return {"id": p.id, "slug": p.slug, "display_name": p.display_name, "status": p.status,
            "spray_enabled": p.spray_enabled, "exploit_enabled": p.exploit_enabled}


@router.get("/projects/{project_id}/scope")
async def list_scope(project_id: str, db: AsyncSession = Depends(get_db),
                     user: User = Depends(get_current_user)) -> dict:
    rows = (await db.execute(select(ScopeTarget).where(ScopeTarget.project_id == project_id))).scalars().all()
    return {"scope": [{"id": s.id, "target": s.target, "kind": s.kind, "is_entry": s.is_entry} for s in rows]}


@router.post("/projects/{project_id}/scope")
async def add_scope(project_id: str, body: ScopeBody, db: AsyncSession = Depends(get_db),
                    user: User = Depends(get_current_user)) -> dict:
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
    return {"id": row.id, "target": row.target, "kind": row.kind}
