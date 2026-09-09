"""settings router — API surface scaffolded per DESIGN §6.2; bodies land in the marked phase."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["settings"])


def _todo() -> dict:
    raise HTTPException(status_code=501, detail="scaffold: implemented in a later phase")

@router.get("/settings")
async def settings_get_settings() -> dict:
    return _todo()

@router.patch("/settings")
async def settings_patch_settings() -> dict:
    return _todo()

