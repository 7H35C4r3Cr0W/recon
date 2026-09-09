"""findings router — API surface scaffolded per DESIGN §6.2; bodies land in the marked phase."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["findings"])


def _todo() -> dict:
    raise HTTPException(status_code=501, detail="scaffold: implemented in a later phase")

@router.get("/projects/{project_id}/findings")
async def findings_get_projects_project_id_findings() -> dict:
    return _todo()

@router.post("/projects/{project_id}/findings")
async def findings_post_projects_project_id_findings() -> dict:
    return _todo()

@router.get("/projects/{project_id}/services")
async def findings_get_projects_project_id_services() -> dict:
    return _todo()

@router.get("/projects/{project_id}/graph")
async def findings_get_projects_project_id_graph() -> dict:
    return _todo()

