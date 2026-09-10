"""FastAPI auth + authorization dependencies.

Authentication is enforced (a valid session is required). Per-project authorization is enforced by
``require_project_member`` / ``require_run_access``: a global admin, the project owner, or an explicit
project member may act; everyone else gets 404 (so project existence isn't leaked). The RBAC
*capability* matrix (viewer/operator/owner granularity) lives in ``nabu_agent.rbac`` and is applied by
``require_project_perm`` / ``require_run_perm`` on the mutating endpoints (run start/cancel, scope
edit, checkpoint decide), so a viewer can watch but not act.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Depends, HTTPException, Path, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent.auth import sessions
from nabu_agent.db.models import Project, ProjectMember, Run, User
from nabu_agent.db.session import get_db
from nabu_agent.rbac import Perm, ProjectRole, Role, can


async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    sid = request.cookies.get(sessions.COOKIE_NAME)
    user_id = await sessions.resolve_session(sid)
    if not user_id:
        raise HTTPException(status_code=401, detail="not authenticated")
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="inactive or unknown user")
    return user


async def _is_member(db: AsyncSession, user: User, project_id: str) -> bool:
    """A global admin, the project owner, or an explicit member may act on a project."""
    if user.role == "admin":
        return True
    proj = (await db.execute(select(Project).where(Project.id == project_id))).scalar_one_or_none()
    if proj is None:
        return False
    if proj.owner_id == user.id:
        return True
    m = (await db.execute(select(ProjectMember).where(
        ProjectMember.project_id == project_id, ProjectMember.user_id == user.id))).scalar_one_or_none()
    return m is not None


async def require_project_member(project_id: str = Path(...), db: AsyncSession = Depends(get_db),
                                 user: User = Depends(get_current_user)) -> str:
    """Authorize the caller for /projects/{project_id}/*. Returns project_id; 404 for non-members."""
    if not await _is_member(db, user, project_id):
        raise HTTPException(status_code=404, detail="project not found")
    return project_id


async def require_project_owner(project_id: str = Path(...), db: AsyncSession = Depends(get_db),
                                user: User = Depends(get_current_user)) -> str:
    """Owner-or-admin guard (stronger than membership) for destructive project ops like delete."""
    if user.role == "admin":
        return project_id
    proj = (await db.execute(select(Project).where(Project.id == project_id))).scalar_one_or_none()
    if proj is None or proj.owner_id != user.id:
        raise HTTPException(status_code=404, detail="project not found")
    return project_id


async def require_run_access(run_id: str = Path(...), db: AsyncSession = Depends(get_db),
                             user: User = Depends(get_current_user)) -> Run:
    """Authorize the caller for /runs/{run_id}: they must be a member of the run's project."""
    run = (await db.execute(select(Run).where(Run.id == run_id))).scalar_one_or_none()
    if run is None or not await _is_member(db, user, run.project_id):
        raise HTTPException(status_code=404, detail="run not found")
    return run


async def require_admin(user: User = Depends(get_current_user)) -> User:
    """Global-admin-only guard for platform admin endpoints."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    return user


# --- capability (RBAC) authorization ------------------------------------------------------------
# Membership is binary (above); these add the per-project ROLE granularity from nabu_agent.rbac so a
# viewer can watch but not start/cancel/edit. A global admin and the project owner always pass.
async def _project_role(db: AsyncSession, user: User, project_id: str) -> ProjectRole | None:
    """The caller's effective project role, or None if they're not a member (project hidden as 404)."""
    if user.role == "admin":
        return ProjectRole.OWNER
    proj = (await db.execute(select(Project).where(Project.id == project_id))).scalar_one_or_none()
    if proj is None:
        return None
    if proj.owner_id == user.id:
        return ProjectRole.OWNER
    m = (await db.execute(select(ProjectMember).where(
        ProjectMember.project_id == project_id, ProjectMember.user_id == user.id))).scalar_one_or_none()
    if m is None:
        return None
    try:
        return ProjectRole(m.role)
    except ValueError:
        return ProjectRole.VIEWER  # unknown stored role → least privilege


def _global_role(user: User) -> Role:
    return Role.ADMIN if user.role == "admin" else Role.OPERATOR


def require_project_perm(perm: Perm) -> Callable[..., Awaitable[str]]:
    """Dependency factory for a project-scoped endpoint: the caller must have `perm` for the project
    in the {project_id} path. Returns project_id; 404 for non-members, 403 for insufficient role."""
    async def _dep(project_id: str = Path(...), db: AsyncSession = Depends(get_db),
                   user: User = Depends(get_current_user)) -> str:
        role = await _project_role(db, user, project_id)
        if role is None:
            raise HTTPException(status_code=404, detail="project not found")
        if not can(role, perm, global_role=_global_role(user)):
            raise HTTPException(status_code=403, detail=f"your project role ({role}) may not {perm}")
        return project_id
    return _dep


def require_run_perm(perm: Perm) -> Callable[..., Awaitable[Run]]:
    """Dependency factory for a run-scoped endpoint: the caller must have `perm` for the run's
    project. Returns the Run; 404 if not a member, 403 for insufficient role."""
    async def _dep(run_id: str = Path(...), db: AsyncSession = Depends(get_db),
                   user: User = Depends(get_current_user)) -> Run:
        run = (await db.execute(select(Run).where(Run.id == run_id))).scalar_one_or_none()
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        role = await _project_role(db, user, run.project_id)
        if role is None:
            raise HTTPException(status_code=404, detail="run not found")
        if not can(role, perm, global_role=_global_role(user)):
            raise HTTPException(status_code=403, detail=f"your project role ({role}) may not {perm}")
        return run
    return _dep
