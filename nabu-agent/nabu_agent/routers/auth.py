"""auth router — API surface scaffolded per DESIGN §6.2; bodies land in the marked phase."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["auth"])


def _todo() -> dict:
    raise HTTPException(status_code=501, detail="scaffold: implemented in a later phase")

@router.get("/auth/providers")
async def auth_get_auth_providers() -> dict:
    return _todo()

@router.post("/auth/login")
async def auth_post_auth_login() -> dict:
    return _todo()

@router.get("/auth/oidc/login")
async def auth_get_auth_oidc_login() -> dict:
    return _todo()

@router.get("/auth/oidc/callback")
async def auth_get_auth_oidc_callback() -> dict:
    return _todo()

@router.post("/auth/logout")
async def auth_post_auth_logout() -> dict:
    return _todo()

@router.get("/auth/me")
async def auth_get_auth_me() -> dict:
    return _todo()

@router.post("/auth/refresh")
async def auth_post_auth_refresh() -> dict:
    return _todo()

