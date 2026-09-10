"""Liveness + readiness probes."""
from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness — the process is up. No dependency checks."""
    return {"status": "ok"}


@router.get("/health/ready")
async def ready() -> dict[str, object]:
    """Readiness — DB reachable, Redis reachable, engine imports headless, workspace writable.

    Each check is best-effort and reported individually so a scaffold boot without every dependency
    still returns a useful body (the aggregate ``ready`` flag is the AND of all checks).
    """
    checks: dict[str, bool] = {}

    try:
        from nabu_agent.db.session import engine
        async with engine().connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception:
        checks["database"] = False

    try:
        import redis.asyncio as aioredis

        from nabu_agent.settings import get_settings
        client = aioredis.from_url(get_settings().redis_url)
        checks["redis"] = bool(await client.ping())
        await client.aclose()
    except Exception:
        checks["redis"] = False

    try:
        import sys

        import oscprecon.shell  # noqa: F401
        checks["engine"] = "PySide6" not in sys.modules
    except Exception:
        checks["engine"] = False

    try:
        import os

        from nabu_agent.settings import get_settings
        checks["workspace"] = os.access(get_settings().workspace, os.W_OK)
    except Exception:
        checks["workspace"] = False

    return {"ready": all(checks.values()), "checks": checks}


@router.get("/llm/health")
async def llm_health() -> dict:
    """Report the configured brain (no secret). ``configured`` is True once NABU_LLM_BASE_URL is set;
    the owner attaches the internal OpenAI-compatible endpoint there. A live ping is a Phase-4 add."""
    from nabu_agent.settings import get_settings
    s = get_settings().llm
    return {"provider": s.provider, "model": s.model, "base_url": s.base_url,
            "configured": bool(s.base_url), "streaming": s.stream}
