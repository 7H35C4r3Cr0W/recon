"""Admin LLM ("brain") setup form: save the connection from the UI (applied at runtime, no restart),
test-fire it (incl. before saving), and confirm the api key is encrypted at rest + never returned."""
from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio


class _FakeProvider:
    model = "gpt-5.1"

    async def chat(self, request):
        from nabu_agent.llm.base import ChatResponse, Usage
        return ChatResponse(content="OK", tool_calls=[], finish_reason="stop",
                            usage=Usage(prompt_tokens=5, completion_tokens=1, total_tokens=6), model=self.model)

    async def aclose(self):
        return None


def _fake_build(monkeypatch, captured: dict):
    from nabu_agent.llm import factory

    def _build(settings):
        captured["base_url"] = settings.base_url
        captured["api_key"] = settings.api_key.get_secret_value()
        captured["model"] = settings.model
        return _FakeProvider()

    monkeypatch.setattr(factory, "build_provider", _build)


async def _login_admin(client):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})


async def test_save_test_and_effective_config_roundtrip(client, monkeypatch):
    captured: dict = {}
    _fake_build(monkeypatch, captured)
    await _login_admin(client)

    # nothing saved yet
    cfg0 = (await client.get("/api/admin/llm/config")).json()
    assert cfg0["saved"] is False

    # test BEFORE saving — inline values, not persisted
    t = await client.post("/api/admin/llm/test", json={
        "base_url": "https://llm.internal/v1", "api_key": "sk-secret-123", "model": "gpt-5.1"})
    assert t.status_code == 200 and t.json()["ok"] is True
    assert t.json()["usage"]["total_tokens"] == 6 and t.json()["latency_ms"] >= 0
    assert captured["base_url"] == "https://llm.internal/v1" and captured["api_key"] == "sk-secret-123"
    assert (await client.get("/api/admin/llm/config")).json()["saved"] is False  # test did NOT save

    # SAVE it
    r = await client.put("/api/admin/llm/config", json={
        "base_url": "https://llm.internal/v1", "model": "gpt-5.1", "api_key": "sk-secret-123",
        "organization": "corp", "temperature": 0.1})
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "saved" and body["configured"] is True and body["has_api_key"] is True
    assert body["base_url"] == "https://llm.internal/v1" and body["model"] == "gpt-5.1"
    assert "api_key" not in body and "sk-secret-123" not in str(body)   # key NEVER returned

    # the key is ENCRYPTED at rest (not stored in plaintext)
    from nabu_agent.db.models import AppSetting
    from nabu_agent.db.session import sessionmaker
    from sqlalchemy import select
    async with sessionmaker()() as db:
        row = (await db.execute(select(AppSetting).where(AppSetting.key == "llm"))).scalar_one()
    assert row.value.get("api_key_enc") and "sk-secret-123" not in str(row.value)

    # the saved config now drives a provider build (effective settings decrypt the key)
    from nabu_agent.services import llm_config as cfg
    eff = await cfg.effective_llm_settings()
    assert eff.base_url == "https://llm.internal/v1" and eff.api_key.get_secret_value() == "sk-secret-123"

    # test the SAVED config (no inline values)
    t2 = await client.post("/api/admin/llm/test", json={})
    assert t2.json()["ok"] is True and captured["base_url"] == "https://llm.internal/v1"

    # re-save WITHOUT a key keeps the existing one
    await client.put("/api/admin/llm/config", json={"base_url": "https://llm.internal/v1", "model": "gpt-5.2"})
    eff2 = await cfg.effective_llm_settings()
    assert eff2.model == "gpt-5.2" and eff2.api_key.get_secret_value() == "sk-secret-123"

    # DELETE reverts to env
    d = await client.delete("/api/admin/llm/config")
    assert d.status_code == 200 and d.json()["saved"] is False


async def test_test_fire_without_config_is_clean(client, monkeypatch):
    _fake_build(monkeypatch, {})
    await _login_admin(client)
    r = await client.post("/api/admin/llm/test", json={})   # nothing configured
    assert r.status_code == 200 and r.json()["ok"] is False and r.json()["configured"] is False


async def test_non_admin_cannot_configure_llm(client, app_ctx, monkeypatch):
    from nabu_agent.auth.providers import hash_password
    from nabu_agent.db.models import User
    from nabu_agent.db.session import sessionmaker
    app, _ = app_ctx
    await _login_admin(client)
    async with sessionmaker()() as db:
        db.add(User(email="op@c.io", display_name="op", role="operator", auth_source="local",
                    password_hash=hash_password("pw")))
        await db.commit()
    op = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    await op.post("/api/auth/login", json={"email": "op@c.io", "password": "pw"})
    assert (await op.get("/api/admin/llm/config")).status_code == 403
    assert (await op.put("/api/admin/llm/config",
            json={"base_url": "https://x/v1"})).status_code == 403
    await op.aclose()
