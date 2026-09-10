"""FastAPI auth + authorization dependencies.

Authentication is enforced (a valid session is required). Per-project authorization is enforced by
``require_project_member`` / ``require_run_access``: a global admin, the project owner, or an explicit
project member may act; everyone else gets 404 (so project existence isn't leaked). The RBAC
*capability* matrix (viewer/operator/owner granularity) lives in ``nabu_agent.rbac`` and is layered on
top as endpoints need it.
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, Path, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent.auth import sessions
from nabu_agent.db.models import Project, ProjectMember, Run, User
from nabu_agent.db.session import get_db


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
