"""Auth router — local login/logout/me (+ OIDC scaffolded)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent.auth import sessions
from nabu_agent.auth.deps import get_current_user
from nabu_agent.auth.providers import verify_password
from nabu_agent.db.models import User
from nabu_agent.db.session import get_db
from nabu_agent.settings import get_settings

router = APIRouter(tags=["auth"])


class LoginBody(BaseModel):
    email: str
    password: str


@router.get("/auth/providers")
async def providers() -> dict:
    return {"local": True, "oidc": bool(get_settings().oidc_issuer)}


@router.post("/auth/login")
async def login(body: LoginBody, response: Response, db: AsyncSession = Depends(get_db)) -> dict:
    user = (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    if user is None or not user.password_hash or not verify_password(user.password_hash, body.password):
        raise HTTPException(status_code=401, detail="invalid credentials")
    sid = await sessions.create_session(user.id)
    response.set_cookie(sessions.COOKIE_NAME, sid, httponly=True, samesite="strict",
                        secure=get_settings().env == "production", max_age=get_settings().session_ttl_min * 60)
    return {"id": user.id, "email": user.email, "display_name": user.display_name, "role": user.role}


@router.post("/auth/logout")
async def logout(request: Request, response: Response) -> dict:
    await sessions.destroy_session(request.cookies.get(sessions.COOKIE_NAME))
    response.delete_cookie(sessions.COOKIE_NAME)
    return {"ok": True}


@router.get("/auth/me")
async def me(user: User = Depends(get_current_user)) -> dict:
    return {"id": user.id, "email": user.email, "display_name": user.display_name, "role": user.role}
