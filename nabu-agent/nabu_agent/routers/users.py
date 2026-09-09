"""users router — API surface scaffolded per DESIGN §6.2; bodies land in the marked phase."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["users"])


def _todo() -> dict:
    raise HTTPException(status_code=501, detail="scaffold: implemented in a later phase")

@router.get("/users")
async def users_get_users() -> dict:
    return _todo()

@router.post("/users")
async def users_post_users() -> dict:
    return _todo()

@router.get("/users/{user_id}")
async def users_get_users_user_id() -> dict:
    return _todo()

@router.patch("/users/{user_id}")
async def users_patch_users_user_id() -> dict:
    return _todo()

@router.delete("/users/{user_id}")
async def users_delete_users_user_id() -> dict:
    return _todo()

