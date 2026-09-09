"""creds router — API surface scaffolded per DESIGN §6.2; bodies land in the marked phase."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["creds"])


def _todo() -> dict:
    raise HTTPException(status_code=501, detail="scaffold: implemented in a later phase")

@router.get("/projects/{project_id}/credentials")
async def creds_get_projects_project_id_credentials() -> dict:
    return _todo()

@router.post("/projects/{project_id}/credentials")
async def creds_post_projects_project_id_credentials() -> dict:
    return _todo()

@router.delete("/projects/{project_id}/credentials/{cred_id}")
async def creds_delete_projects_project_id_credentials_cred_id() -> dict:
    return _todo()

