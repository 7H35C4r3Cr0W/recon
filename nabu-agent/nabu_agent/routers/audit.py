"""audit router — API surface scaffolded per DESIGN §6.2; bodies land in the marked phase."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["audit"])


def _todo() -> dict:
    raise HTTPException(status_code=501, detail="scaffold: implemented in a later phase")

@router.get("/audit")
async def audit_get_audit() -> dict:
    return _todo()

@router.get("/projects/{project_id}/activity")
async def audit_get_projects_project_id_activity() -> dict:
    return _todo()

