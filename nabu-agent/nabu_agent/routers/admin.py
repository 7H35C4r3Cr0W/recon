"""Admin-only ops endpoints: storage stats + manual retention trigger."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from nabu_agent.auth.deps import require_admin
from nabu_agent.db.models import User
from nabu_agent.orchestration.retention import run_retention, storage_stats

router = APIRouter(tags=["admin"])


@router.get("/admin/storage")
async def storage(_: User = Depends(require_admin)) -> dict:
    """Row counts for the growth-prone tables."""
    return await storage_stats()


@router.post("/admin/retention")
async def trigger_retention(_: User = Depends(require_admin)) -> dict:
    """Run the retention policies now (also runs hourly on the worker)."""
    return await run_retention()
