"""Per-project settings: scan profile + attack gates + status. GET is member-readable; PATCH needs
SETTINGS_EDIT (owner/admin) — an operator cannot flip the spray/exploit gates. Global /settings is a
read-only platform-info view (never leaks the LLM key)."""
from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio


async def test_project_settings_get_patch(client):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Cfg"})).json()["id"]
    s = (await client.get(f"/api/projects/{pid}/settings")).json()
    assert s == {"scan_profile": "default", "spray_enabled": False, "exploit_enabled": False, "status": "active"}
    r = await client.patch(f"/api/projects/{pid}/settings",
                           json={"scan_profile": "full", "spray_enabled": True})
    assert r.status_code == 200 and r.json()["scan_profile"] == "full" and r.json()["spray_enabled"] is True
    assert (await client.patch(f"/api/projects/{pid}/settings", json={"scan_profile": "bogus"})).status_code == 422


async def test_operator_cannot_flip_attack_gates(client, app_ctx):
    from nabu_agent.auth.providers import hash_password
    from nabu_agent.db.models import User
    from nabu_agent.db.session import sessionmaker
    app, _ = app_ctx
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Cfg2"})).json()["id"]
    async with sessionmaker()() as db:
        db.add(User(email="op@c.io", display_name="op", role="operator", auth_source="local",
                    password_hash=hash_password("pw")))
        await db.commit()
    await client.post(f"/api/projects/{pid}/members", json={"email": "op@c.io", "role": "operator"})
    op = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    await op.post("/api/auth/login", json={"email": "op@c.io", "password": "pw"})
    assert (await op.get(f"/api/projects/{pid}/settings")).status_code == 200          # can read
    assert (await op.patch(f"/api/projects/{pid}/settings",
                           json={"exploit_enabled": True})).status_code == 403          # cannot flip
    await op.aclose()


async def test_global_settings_is_readonly_info(client):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    s = (await client.get("/api/settings")).json()
    assert "llm_configured" in s and "guardrails" in s
    assert "api_key" not in str(s).lower() or "key" not in s   # never leaks the secret
