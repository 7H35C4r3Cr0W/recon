"""Per-project authorization: a non-member cannot see or act on another user's project or run
(closes the IDOR/RBAC findings). Uses two independent httpx clients (separate cookie jars)."""
from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio


async def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def _make_user(email: str, password: str, role: str = "operator") -> str:
    from nabu_agent.auth.providers import hash_password
    from nabu_agent.db.models import User
    from nabu_agent.db.session import sessionmaker
    async with sessionmaker()() as db:
        u = User(email=email, display_name=email, role=role, auth_source="local",
                 password_hash=hash_password(password))
        db.add(u)
        await db.commit()
        return u.id


async def test_non_member_cannot_access_others_project_or_run(app_ctx):
    app, admin = app_ctx
    # user A (admin) creates a project + scope + starts a run
    a = await _client(app)
    await a.post("/api/auth/login", json=admin)
    pid = (await a.post("/api/projects", json={"display_name": "A-only"})).json()["id"]
    await a.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5"})
    run_id = (await a.post(f"/api/projects/{pid}/runs", json={"target": "10.10.10.5", "kind": "demo"})).json()["run_id"]

    # user B is a different, non-member operator
    await _make_user("b@nabu.local", "pw-b")
    b = await _client(app)
    await b.post("/api/auth/login", json={"email": "b@nabu.local", "password": "pw-b"})

    # B sees none of A's projects
    assert (await b.get("/api/projects")).json()["projects"] == []
    # B is refused (404, not 403 — no existence leak) on A's project + run
    assert (await b.get(f"/api/projects/{pid}")).status_code == 404
    assert (await b.get(f"/api/projects/{pid}/scope")).status_code == 404
    assert (await b.post(f"/api/projects/{pid}/runs", json={"target": "10.10.10.5"})).status_code == 404
    assert (await b.get(f"/api/runs/{run_id}")).status_code == 404
    assert (await b.get(f"/api/runs/{run_id}/events")).status_code == 404
    assert (await b.post(f"/api/runs/{run_id}/cancel")).status_code == 404

    # A (owner) still has full access
    assert (await a.get(f"/api/projects/{pid}")).status_code == 200
    assert (await a.get(f"/api/runs/{run_id}")).status_code == 200
    await a.aclose(); await b.aclose()
