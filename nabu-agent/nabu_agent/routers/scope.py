"""scope router — API surface scaffolded per DESIGN §6.2; bodies land in the marked phase."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["scope"])


def _todo() -> dict:
    raise HTTPException(status_code=501, detail="scaffold: implemented in a later phase")

@router.get("/projects/{project_id}/scope")
async def scope_get_projects_project_id_scope() -> dict:
    return _todo()

@router.post("/projects/{project_id}/scope")
async def scope_post_projects_project_id_scope() -> dict:
    return _todo()

@router.delete("/projects/{project_id}/scope/{target_id}")
async def scope_delete_projects_project_id_scope_target_id() -> dict:
    return _todo()

@router.post("/projects/{project_id}/scope/promote")
async def scope_post_projects_project_id_scope_promote() -> dict:
    return _todo()

