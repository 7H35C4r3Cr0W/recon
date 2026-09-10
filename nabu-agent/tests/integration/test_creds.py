"""Credentials vault: add / list / remove, with the SECRET never returned by the API. Operator+ only
(CREDS_VIEW) — a viewer can't see creds."""
from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio


async def test_cred_add_list_masked_remove(client, monkeypatch, tmp_path):
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Vault"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5"})

    r = await client.post(f"/api/projects/{pid}/credentials",
                          json={"username": "svc_sql", "secret": "S3cr3t!", "domain": "CORP", "source": "smb-dump"})
    assert r.status_code == 200
    cred = r.json()
    assert cred["username"] == "svc_sql" and "secret" not in cred        # secret never returned
    assert "S3cr3t" not in str(cred)

    lst = (await client.get(f"/api/projects/{pid}/credentials")).json()["credentials"]
    assert len(lst) == 1 and lst[0]["domain"] == "CORP" and "secret" not in lst[0]
    assert "S3cr3t" not in str(lst)

    assert (await client.delete(f"/api/projects/{pid}/credentials/{cred['id']}")).status_code == 200
    assert (await client.get(f"/api/projects/{pid}/credentials")).json()["credentials"] == []


async def test_viewer_cannot_see_credentials(client, app_ctx, monkeypatch, tmp_path):
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    from nabu_agent.auth.providers import hash_password
    from nabu_agent.db.models import User
    from nabu_agent.db.session import sessionmaker
    app, _ = app_ctx
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Vault2"})).json()["id"]
    async with sessionmaker()() as db:
        db.add(User(email="v@c.io", display_name="v", role="operator", auth_source="local",
                    password_hash=hash_password("pw")))
        await db.commit()
    await client.post(f"/api/projects/{pid}/members", json={"email": "v@c.io", "role": "viewer"})
    v = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    await v.post("/api/auth/login", json={"email": "v@c.io", "password": "pw"})
    assert (await v.get(f"/api/projects/{pid}/credentials")).status_code == 403   # viewer lacks CREDS_VIEW
    await v.aclose()
