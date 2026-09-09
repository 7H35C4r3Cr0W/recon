"""reports router — API surface scaffolded per DESIGN §6.2; bodies land in the marked phase."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["reports"])


def _todo() -> dict:
    raise HTTPException(status_code=501, detail="scaffold: implemented in a later phase")

@router.get("/projects/{project_id}/report")
async def reports_get_projects_project_id_report() -> dict:
    return _todo()

@router.post("/projects/{project_id}/report")
async def reports_post_projects_project_id_report() -> dict:
    return _todo()

@router.get("/projects/{project_id}/artifacts")
async def reports_get_projects_project_id_artifacts() -> dict:
    return _todo()

@router.post("/projects/{project_id}/export")
async def reports_post_projects_project_id_export() -> dict:
    return _todo()

