"""FastAPI auth dependencies. MVP posture: authentication is enforced (a valid session is required);
fine-grained per-project RBAC enforcement is scaffolded and hardened in Phase 3 — the RBAC matrix
lives in ``nabu_agent.rbac`` and is applied at the router boundary as endpoints are built out."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent.auth import sessions
from nabu_agent.db.models import User
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
