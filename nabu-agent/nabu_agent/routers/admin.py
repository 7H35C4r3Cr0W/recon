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
    """Current brain configuration STATUS (never the api key). Drives the admin LLM setup page.
    ``source`` = 'saved' (admin set it in the UI), 'env' (only NABU_LLM_* set), or 'none'."""
    from nabu_agent.services import llm_config as cfg
    return {**await cfg.status(),
            "env_prefix": "NABU_LLM_",
            "required_env": ["NABU_LLM_BASE_URL", "NABU_LLM_API_KEY", "NABU_LLM_MODEL"]}


class LLMConfigBody(BaseModel):
    base_url: str
    model: str = "gpt-5.1"
    api_key: str | None = None            # blank/omitted → keep the currently-saved key
    provider: str = "openai_compatible"
    organization: str = ""
    temperature: float = 0.2
    max_output_tokens: int = 4096
    context_window: int = 128_000
    timeout_read_s: float = 120.0
    tls_verify: bool = True


@router.put("/admin/llm/config")
async def save_llm_config(body: LLMConfigBody, user: User = Depends(require_admin)) -> dict:
    """Save the brain config from the UI — applied on the next provider build, no restart. The api
    key is stored ENCRYPTED and never returned. Leave api_key blank to keep the existing one."""
    from fastapi import HTTPException

    from nabu_agent.services import llm_config as cfg
    if not body.base_url.strip():
        raise HTTPException(status_code=422, detail="base_url is required (your internal endpoint)")
    values = body.model_dump(exclude={"api_key"})
    await cfg.save(values, api_key=body.api_key, updated_by=user.id)
    from nabu_agent import audit
    await audit.record(actor_user_id=user.id, action=audit.SETTINGS_CHANGED, object_type="llm-config",
                       object_id="llm", details={"base_url": body.base_url, "model": body.model,
                                                  "key_set": bool(body.api_key)})
    return {"ok": True, **await cfg.status()}


@router.delete("/admin/llm/config")
async def clear_llm_config(user: User = Depends(require_admin)) -> dict:
    """Delete the saved override and fall back to the NABU_LLM_* env config."""
    from nabu_agent.services import llm_config as cfg
    await cfg.clear()
    from nabu_agent import audit
    await audit.record(actor_user_id=user.id, action=audit.SETTINGS_CHANGED, object_type="llm-config",
                       object_id="llm", details={"cleared": True})
    return {"ok": True, **await cfg.status()}


class LLMTestBody(BaseModel):
    prompt: str = "Reply with the single word: OK"
    # optional inline values to TEST BEFORE SAVING (blank → test the saved/effective config)
    base_url: str | None = None
    api_key: str | None = None
    model: str | None = None
    organization: str | None = None
    tls_verify: bool | None = None


@router.post("/admin/llm/test")
async def llm_test(body: LLMTestBody, _: User = Depends(require_admin)) -> dict:
    """Test-fire the brain: one tiny prompt → success, latency, model, token usage — or a clean
    error. If inline values are supplied they're tested WITHOUT saving (so the admin can validate
    before committing). Never raises (returns ok:false with the reason)."""
    from nabu_agent.llm.base import ChatRequest, Message, Role
    from nabu_agent.llm.factory import build_provider
    from nabu_agent.services import llm_config as cfg

    overrides = {k: v for k, v in {"base_url": body.base_url, "api_key": body.api_key,
                 "model": body.model, "organization": body.organization,
                 "tls_verify": body.tls_verify}.items() if v is not None and v != ""}
    s = await cfg.effective_llm_settings(overrides or None)
    if not s.base_url:
        return {"ok": False, "configured": False,
                "error": "No endpoint yet — enter a Base URL (and API key / model) above, then Test."}
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
        with contextlib.suppress(Exception):
            await provider.aclose()
