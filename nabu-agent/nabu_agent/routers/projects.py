"""projects router — API surface scaffolded per DESIGN §6.2; bodies land in the marked phase."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["projects"])


def _todo() -> dict:
    raise HTTPException(status_code=501, detail="scaffold: implemented in a later phase")

@router.get("/projects")
async def projects_get_projects() -> dict:
    return _todo()

@router.post("/projects")
async def projects_post_projects() -> dict:
    return _todo()

@router.get("/projects/{project_id}")
async def projects_get_projects_project_id() -> dict:
    return _todo()

@router.patch("/projects/{project_id}")
async def projects_patch_projects_project_id() -> dict:
    return _todo()

@router.delete("/projects/{project_id}")
async def projects_delete_projects_project_id() -> dict:
    return _todo()

@router.get("/projects/{project_id}/members")
async def projects_get_projects_project_id_members() -> dict:
    return _todo()

@router.patch("/projects/{project_id}/settings")
async def projects_patch_projects_project_id_settings() -> dict:
    return _todo()

