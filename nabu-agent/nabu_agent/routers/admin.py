"""Admin-only ops endpoints: storage stats, manual retention trigger, and the LLM ("brain") setup +
connection test — so an admin can wire the internal OpenAI-compatible model and validate it (latency
+ token metrics) before turning agent runs loose."""
from __future__ import annotations

import contextlib
import time

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from nabu_agent.auth.deps import require_admin
from nabu_agent.db.models import User
from nabu_agent.orchestration.retention import run_retention, storage_stats
from nabu_agent.settings import get_settings

router = APIRouter(tags=["admin"])


@router.get("/admin/storage")
async def storage(_: User = Depends(require_admin)) -> dict:
    """Row counts for the growth-prone tables."""
    return await storage_stats()


@router.post("/admin/retention")
async def trigger_retention(_: User = Depends(require_admin)) -> dict:
    """Run the retention policies now (also runs hourly on the worker)."""
    return await run_retention()


@router.get("/admin/llm/config")
async def llm_config(_: User = Depends(require_admin)) -> dict:
    """Current brain configuration STATUS (never the api key). Drives the admin LLM setup page."""
    s = get_settings().llm
    return {
        "provider": s.provider,
        "configured": bool(s.base_url),           # base_url is the one required field
        "base_url": s.base_url,                   # not a secret; shown so the admin can confirm it
        "model": s.model,
        "organization": s.organization or None,
        "has_api_key": bool(s.api_key.get_secret_value()),   # bool only — the key is never returned
        "temperature": s.temperature,
        "max_output_tokens": s.max_output_tokens,
        "context_window": s.context_window,
        "timeout_read_s": s.timeout_read_s,
        "tls_verify": s.tls_verify,
        "env_prefix": "NABU_LLM_",
        "required_env": ["NABU_LLM_BASE_URL", "NABU_LLM_API_KEY", "NABU_LLM_MODEL"],
    }


class LLMTestBody(BaseModel):
    prompt: str = "Reply with the single word: OK"


@router.post("/admin/llm/test")
async def llm_test(body: LLMTestBody, _: User = Depends(require_admin)) -> dict:
    """Test-fire the configured brain: send one tiny prompt and report success, latency, model, and
    token usage — or a clean error. Never raises (returns ok:false with the reason), so a
    misconfiguration is diagnosable from the UI instead of a 500."""
    from nabu_agent.llm.base import ChatRequest, Message, Role
    from nabu_agent.llm.factory import build_provider

    s = get_settings().llm
    if not s.base_url:
        return {"ok": False, "configured": False,
                "error": "LLM not configured — set NABU_LLM_BASE_URL (and NABU_LLM_API_KEY / "
                         "NABU_LLM_MODEL), then restart the api + worker."}
    try:
        provider = build_provider(s)
    except Exception as exc:
        return {"ok": False, "configured": True, "error": f"could not build the provider: {exc}"}

    t0 = time.perf_counter()
    try:
        resp = await provider.chat(ChatRequest(
            messages=[Message(role=Role.USER, content=body.prompt)],
            max_output_tokens=32, temperature=0.0))
        return {
            "ok": True, "configured": True,
            "latency_ms": round((time.perf_counter() - t0) * 1000),
            "model": resp.model, "finish_reason": resp.finish_reason,
            "content": (resp.content or "")[:500],
            "usage": {"prompt_tokens": resp.usage.prompt_tokens,
                      "completion_tokens": resp.usage.completion_tokens,
                      "total_tokens": resp.usage.total_tokens,
                      "estimated": resp.usage.estimated},
        }
    except Exception as exc:
        return {"ok": False, "configured": True,
                "latency_ms": round((time.perf_counter() - t0) * 1000), "error": str(exc)[:400]}
    finally:
        client = getattr(provider, "_client", None)   # factory builds an httpx client per call; close it
        if client is not None:
            with contextlib.suppress(Exception):
                await client.aclose()
