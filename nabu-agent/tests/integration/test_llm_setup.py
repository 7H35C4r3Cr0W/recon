"""Admin LLM ('brain') setup: config status (never the key) + test-fire. With no LLM configured the
test-fire returns a clean ok:false + reason (not a 500); both endpoints are admin-only."""
from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio


async def test_llm_config_and_test_when_unconfigured(client):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    cfg = (await client.get("/api/admin/llm/config")).json()
    assert cfg["configured"] is False               # no NABU_LLM_BASE_URL in tests
    assert cfg["required_env"] == ["NABU_LLM_BASE_URL", "NABU_LLM_API_KEY", "NABU_LLM_MODEL"]
    assert "api_key" not in cfg                      # the key is never returned, only has_api_key
    assert cfg["has_api_key"] is False

    r = await client.post("/api/admin/llm/test", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False and body["configured"] is False and "NABU_LLM_BASE_URL" in body["error"]


async def test_llm_test_fire_reports_metrics_with_a_fake_brain(client, monkeypatch):
    from nabu_agent.llm.base import ChatResponse, Usage
    from nabu_agent.llm import factory

    class _Fake:
        model = "gpt-5.1"
        _client = httpx.AsyncClient()
        async def chat(self, request):
            return ChatResponse(content="OK", tool_calls=[], finish_reason="stop",
                                usage=Usage(prompt_tokens=7, completion_tokens=1, total_tokens=8), model=self.model)
    monkeypatch.setattr(factory, "build_provider", lambda s: _Fake())
    monkeypatch.setenv("NABU_LLM_BASE_URL", "http://brain.internal/v1")
    from nabu_agent.settings import get_settings
    get_settings.cache_clear()
    try:
        await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
        body = (await client.post("/api/admin/llm/test", json={"prompt": "ping"})).json()
        assert body["ok"] is True and body["model"] == "gpt-5.1"
        assert body["usage"]["total_tokens"] == 8 and body["content"] == "OK"
        assert isinstance(body["latency_ms"], int)
    finally:
        get_settings.cache_clear()


async def test_llm_endpoints_admin_only(client, app_ctx):
    from nabu_agent.auth.providers import hash_password
    from nabu_agent.db.models import User
    from nabu_agent.db.session import sessionmaker
    app, _ = app_ctx
    async with sessionmaker()() as db:
        db.add(User(email="op@c.io", display_name="op", role="operator", auth_source="local",
                    password_hash=hash_password("pw")))
        await db.commit()
    b = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    await b.post("/api/auth/login", json={"email": "op@c.io", "password": "pw"})
    assert (await b.get("/api/admin/llm/config")).status_code == 403
    assert (await b.post("/api/admin/llm/test", json={})).status_code == 403
    await b.aclose()
