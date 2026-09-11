"""Auth router — local login/logout/me (+ OIDC scaffolded)."""
from __future__ import annotations

import contextlib

import structlog as _structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nabu_agent import audit, bus
from nabu_agent.auth import oidc, sessions
from nabu_agent.auth.deps import get_current_user
from nabu_agent.auth.providers import verify_password
from nabu_agent.db.models import User
from nabu_agent.db.session import get_db
from nabu_agent.db.session import get_db as _get_db
from nabu_agent.settings import get_settings

_slog = _structlog.get_logger("nabu_agent.auth")

router = APIRouter(tags=["auth"])


class LoginBody(BaseModel):
    email: str
    password: str


@router.get("/auth/providers")
async def providers() -> dict:
    return {"local": True, "oidc": bool(get_settings().oidc_issuer)}


@router.post("/auth/login")
async def login(body: LoginBody, request: Request, response: Response,
                db: AsyncSession = Depends(get_db)) -> dict:
    ip = request.client.host if request.client else None
    ip_s = ip or "unknown"
    # brute-force throttle: too many recent failures for this (ip, email) → refuse before verifying
    if await bus.login_failure_count(ip_s, body.email) >= bus.LOGIN_MAX_FAILURES:
        await audit.record(actor_user_id=None, action=audit.LOGIN_FAILED, result="denied",
                           actor_ip=ip, details={"email": body.email, "reason": "rate-limited"})
        raise HTTPException(status_code=429, detail="too many attempts — try again later",
                            headers={"Retry-After": str(bus.LOGIN_WINDOW_S)})
    user = (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    if (user is None or not user.is_active or not user.password_hash
            or not verify_password(user.password_hash, body.password)):
        await bus.register_login_failure(ip_s, body.email)
        await audit.record(actor_user_id=(user.id if user else None), action=audit.LOGIN_FAILED,
                           result="denied", actor_ip=ip, details={"email": body.email})
        raise HTTPException(status_code=401, detail="invalid credentials")
    await bus.clear_login_failures(ip_s, body.email)
    sid = await sessions.create_session(user.id)
    response.set_cookie(sessions.COOKIE_NAME, sid, httponly=True, samesite="strict",
                        secure=get_settings().env == "production", max_age=get_settings().session_ttl_min * 60)
    await audit.record(actor_user_id=user.id, action=audit.LOGIN, actor_ip=ip)
    return {"id": user.id, "email": user.email, "display_name": user.display_name, "role": user.role}


@router.post("/auth/logout")
async def logout(request: Request, response: Response) -> dict:
    sid = request.cookies.get(sessions.COOKIE_NAME)
    uid = await sessions.resolve_session(sid)
    await sessions.destroy_session(sid)
    response.delete_cookie(sessions.COOKIE_NAME)
    await audit.record(actor_user_id=uid, action=audit.LOGOUT,
                       actor_ip=request.client.host if request.client else None)
    return {"ok": True}


@router.get("/auth/me")
async def me(user: User = Depends(get_current_user)) -> dict:
    return {"id": user.id, "email": user.email, "display_name": user.display_name, "role": user.role}


def _set_session_cookie(response: Response, sid: str) -> None:
    s = get_settings()
    response.set_cookie(sessions.COOKIE_NAME, sid, httponly=True, samesite="lax",
                        secure=s.env == "production", max_age=s.session_ttl_min * 60)


@router.get("/auth/oidc/login")
async def oidc_login(request: Request):
    """Redirect to the IdP's authorize endpoint. 404 if OIDC isn't configured."""
    if not oidc.is_configured():
        raise HTTPException(status_code=404, detail="OIDC is not configured")
    s = get_settings()
    redirect_uri = s.oidc_redirect_url or str(request.url_for("oidc_callback"))
    return await oidc.client().authorize_redirect(request, redirect_uri)


@router.get("/auth/oidc/callback", name="oidc_callback")
async def oidc_callback(request: Request, db: AsyncSession = Depends(_get_db)):
    """Exchange the code, validate the ID token, JIT-provision the user, start a session, redirect
    to the SPA. Any failure is a 401 (never a stack trace)."""
    if not oidc.is_configured():
        raise HTTPException(status_code=404, detail="OIDC is not configured")
    try:
        token = await oidc.client().authorize_access_token(request)
    except Exception as exc:  # bad state/code/nonce, token exchange failure, etc.
        _slog.warning("oidc-login-failed", error=str(exc), exc_info=True)
        with contextlib.suppress(Exception):
            await audit.record(actor_user_id=None, action=audit.LOGIN_FAILED, result="denied",
                               actor_ip=request.client.host if request.client else None,
                               details={"reason": "oidc-exchange-failed"})
        raise HTTPException(status_code=401, detail="OIDC login failed") from exc
    claims = token.get("userinfo") or {}
    issuer = claims.get("iss") or get_settings().oidc_issuer
    subject = claims.get("sub")
    if not subject:
        raise HTTPException(status_code=401, detail="OIDC token missing subject")
    user = await oidc.provision_user(db, issuer=issuer, subject=subject,
                                     email=claims.get("email", ""), name=claims.get("name", ""))
    sid = await sessions.create_session(user.id)
    response = RedirectResponse(url="/", status_code=303)
    _set_session_cookie(response, sid)
    return response


@router.post("/auth/oidc/backchannel-logout")
async def oidc_backchannel_logout(request: Request, db: AsyncSession = Depends(_get_db)) -> JSONResponse:
    """OIDC Back-Channel Logout: the IdP POSTs a signed logout_token (server-to-server, no browser);
    we validate it and revoke ALL of that user's sessions here. 200 on success, 400 on a bad token."""
    if not oidc.is_configured():
        raise HTTPException(status_code=404, detail="OIDC is not configured")
    form = await request.form()
    token = form.get("logout_token")
    if not token:
        raise HTTPException(status_code=400, detail="missing logout_token")
    try:
        claims = await oidc.validate_logout_token(str(token))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid logout_token: {exc}") from exc
    revoked = 0
    sub = claims.get("sub")
    if sub:
        user = (await db.execute(select(User).where(
            User.oidc_issuer == claims.get("iss"), User.oidc_subject == sub))).scalar_one_or_none()
        if user:
            revoked = await sessions.destroy_user_sessions(user.id)
    resp = JSONResponse({"revoked": revoked})
    resp.headers["Cache-Control"] = "no-store"   # never cache a logout response
    return resp
