"""Platform audit trail: the key actions (login, project create, scope add, run start, checkpoint
decision) land in audit_log and are readable via the per-project activity view (members) and the
global audit view (admin only)."""
from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio


async def test_activity_trail_records_key_actions(client):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Audited"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5"})
    await client.post(f"/api/projects/{pid}/runs", json={"target": "10.10.10.5", "kind": "demo"})

    acts = [a["action"] for a in (await client.get(f"/api/projects/{pid}/activity")).json()["activity"]]
    assert "project-created" in acts
    assert "scope-added" in acts
    assert "run-started" in acts
    # the login (project-less) is in the global trail, not the per-project one
    assert "login" not in acts

    audit = (await client.get("/api/audit")).json()["audit"]
    assert any(a["action"] == "login" and a["result"] == "success" for a in audit)


async def test_failed_login_is_audited_denied(client):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "WRONG"})
    # log in properly to read the trail
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    audit = (await client.get("/api/audit?action=login-failed")).json()["audit"]
    assert any(a["result"] == "denied" and a["details"].get("email") == "admin@nabu.local" for a in audit)


async def test_global_audit_is_admin_only(client, app_ctx):
    from nabu_agent.auth.providers import hash_password
    from nabu_agent.db.models import User
    from nabu_agent.db.session import sessionmaker

    app, _ = app_ctx
    async with sessionmaker()() as db:
        db.add(User(email="op@corp.local", display_name="op", role="operator", auth_source="local",
                    password_hash=hash_password("pw")))
        await db.commit()
    b = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    await b.post("/api/auth/login", json={"email": "op@corp.local", "password": "pw"})
    assert (await b.get("/api/audit")).status_code == 403   # non-admin refused the global trail
    await b.aclose()
