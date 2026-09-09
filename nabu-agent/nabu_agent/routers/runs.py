"""runs router — API surface scaffolded per DESIGN §6.2; bodies land in the marked phase."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["runs"])


def _todo() -> dict:
    raise HTTPException(status_code=501, detail="scaffold: implemented in a later phase")

@router.get("/projects/{project_id}/runs")
async def runs_get_projects_project_id_runs() -> dict:
    return _todo()

@router.post("/projects/{project_id}/runs")
async def runs_post_projects_project_id_runs() -> dict:
    return _todo()

@router.get("/runs/{run_id}")
async def runs_get_runs_run_id() -> dict:
    return _todo()

@router.get("/runs/{run_id}/tasks")
async def runs_get_runs_run_id_tasks() -> dict:
    return _todo()

@router.post("/runs/{run_id}/cancel")
async def runs_post_runs_run_id_cancel() -> dict:
    return _todo()

@router.get("/runs/{run_id}/usage")
async def runs_get_runs_run_id_usage() -> dict:
    return _todo()

@router.get("/projects/{project_id}/checkpoints")
async def runs_get_projects_project_id_checkpoints() -> dict:
    return _todo()

@router.post("/projects/{project_id}/checkpoints/{checkpoint_id}/decision")
async def runs_post_projects_project_id_checkpoints_checkpoint_id_decision() -> dict:
    return _todo()

