"""Global user provisioning — admin only. Create local login accounts, list users, change a user's
global role / activation / password. Users are soft-deactivated (never hard-deleted) because they're
referenced by projects, runs and the audit trail. A guard prevents locking out the last admin."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent import audit
from nabu_agent.auth.deps import require_admin
from nabu_agent.auth.providers import hash_password
from nabu_agent.auth.sessions import destroy_user_sessions
from nabu_agent.db.models import User
from nabu_agent.db.session import get_db

router = APIRouter(tags=["users"])

_ROLES = ("admin", "operator", "viewer")


class UserCreate(BaseModel):
    email: str
    password: str
    display_name: str = ""
    role: str = "operator"


class UserPatch(BaseModel):
    display_name: str | None = None
    role: str | None = None
    is_active: bool | None = None
    password: str | None = None


def _view(u: User) -> dict:
    return {"id": u.id, "email": u.email, "display_name": u.display_name, "role": u.role,
            "auth_source": u.auth_source, "is_active": u.is_active,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            "created_at": u.created_at.isoformat() if u.created_at else None}


async def _active_admin_count(db: AsyncSession) -> int:
    return int((await db.execute(select(func.count()).select_from(User).where(
        User.role == "admin", User.is_active.is_(True)))).scalar() or 0)


async def _guard_last_admin(db: AsyncSession, target: User, *, new_role: str | None, new_active: bool | None) -> None:
    """Refuse a change that would remove the FINAL active admin (total lockout)."""
    losing_admin = target.role == "admin" and target.is_active and (
        (new_role is not None and new_role != "admin") or new_active is False)
    if losing_admin and await _active_admin_count(db) <= 1:
        raise HTTPException(status_code=409, detail="cannot remove the last active admin")


@router.get("/users")
async def list_users(db: AsyncSession = Depends(get_db), _admin: User = Depends(require_admin)) -> dict:
    rows = (await db.execute(select(User).order_by(User.created_at))).scalars().all()
    return {"users": [_view(u) for u in rows]}


@router.post("/users")
async def create_user(body: UserCreate, db: AsyncSession = Depends(get_db),
                      admin: User = Depends(require_admin)) -> dict:
    if body.role not in _ROLES:
        raise HTTPException(status_code=422, detail=f"role must be one of {_ROLES}")
    if not body.email or not body.password:
        raise HTTPException(status_code=422, detail="email and password are required")
    exists = (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    if exists is not None:
        raise HTTPException(status_code=409, detail="a user with that email already exists")
    u = User(email=body.email, display_name=body.display_name or body.email.split("@")[0],
             role=body.role, auth_source="local", password_hash=hash_password(body.password))
    db.add(u)
    await db.commit()
    await audit.record(actor_user_id=admin.id, action=audit.USER_CREATED, object_type="user",
                       object_id=u.id, details={"email": u.email, "role": u.role})
    return _view(u)


@router.get("/users/{user_id}")
async def get_user(user_id: str, db: AsyncSession = Depends(get_db),
                   _admin: User = Depends(require_admin)) -> dict:
    u = await db.get(User, user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="user not found")
    return _view(u)


@router.patch("/users/{user_id}")
async def update_user(user_id: str, body: UserPatch, db: AsyncSession = Depends(get_db),
                      admin: User = Depends(require_admin)) -> dict:
    u = await db.get(User, user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="user not found")
    if body.role is not None and body.role not in _ROLES:
        raise HTTPException(status_code=422, detail=f"role must be one of {_ROLES}")
    await _guard_last_admin(db, u, new_role=body.role, new_active=body.is_active)
    changed: dict = {}
    if body.display_name is not None:
        u.display_name = body.display_name
        changed["display_name"] = body.display_name
    if body.role is not None:
        u.role = body.role
        changed["role"] = body.role
    if body.is_active is not None:
        u.is_active = body.is_active
        changed["is_active"] = body.is_active
    if body.password:
        u.password_hash = hash_password(body.password)
        changed["password"] = "reset"
    await db.commit()
    # revoke live sessions when an account is disabled or its password is reset
    if body.is_active is False or body.password:
        await destroy_user_sessions(u.id)
    if changed:
        await audit.record(actor_user_id=admin.id, action=audit.USER_UPDATED, object_type="user",
                           object_id=u.id, details=changed)
    return _view(u)


@router.delete("/users/{user_id}")
async def deactivate_user(user_id: str, db: AsyncSession = Depends(get_db),
                          admin: User = Depends(require_admin)) -> dict:
    """Soft-delete: deactivate the account (they're referenced by projects/runs/audit, so never hard
    -deleted) and revoke their live sessions."""
    u = await db.get(User, user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="user not found")
    await _guard_last_admin(db, u, new_role=None, new_active=False)
    u.is_active = False
    await db.commit()
    await destroy_user_sessions(u.id)
    await audit.record(actor_user_id=admin.id, action=audit.USER_UPDATED, object_type="user",
                       object_id=u.id, details={"is_active": False})
    return {"deactivated": True}
