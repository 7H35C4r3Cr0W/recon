"""catalog router — API surface scaffolded per DESIGN §6.2; bodies land in the marked phase."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["catalog"])


def _todo() -> dict:
    raise HTTPException(status_code=501, detail="scaffold: implemented in a later phase")

@router.get("/projects/{project_id}/suggestions")
async def catalog_get_projects_project_id_suggestions() -> dict:
    return _todo()

@router.get("/projects/{project_id}/catalog")
async def catalog_get_projects_project_id_catalog() -> dict:
    return _todo()

@router.get("/catalog/services/{key}")
async def catalog_get_catalog_services_key() -> dict:
    return _todo()

