"""Settings router. There is no runtime-mutable GLOBAL config (app config is env-based and
immutable at runtime), so /settings is a READ-ONLY platform-info view. The settings that CAN change
are per-project (scan profile + spray/exploit gates + status) and live on the project routes
(GET/PATCH /projects/{id}/settings)."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from nabu_agent.auth.deps import get_current_user
from nabu_agent.db.models import User
from nabu_agent.orchestration.limits import RunLimits
from nabu_agent.settings import get_settings

router = APIRouter(tags=["settings"])


@router.get("/settings")
async def platform_settings(_user: User = Depends(get_current_user)) -> dict:
    """Non-sensitive platform info: environment, whether the LLM brain is configured (never the key),
    the scan profiles, and the host-fan-out guardrails. Mutable settings are per-project."""
    s = get_settings()
    limits = RunLimits()
    return {
        "env": s.env,
        "version": "0.1.0",
        "llm_configured": bool(s.llm.base_url),          # bool only — the api key is never exposed
        "scan_profiles": ["quick", "default", "exam", "full"],
        "guardrails": {
            "max_hosts": limits.max_hosts,
            "approval_required_above_hosts": limits.approval_required_above_hosts,
            "max_concurrent_hosts": limits.max_concurrent_hosts,
            "max_enum_per_host": limits.max_enum_per_host,
            "max_total_tasks": limits.max_total_tasks,
        },
        "attack_policy": "spray/exploit require BOTH the per-project gate AND a human-approved checkpoint",
    }
