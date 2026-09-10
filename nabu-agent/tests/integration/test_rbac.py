"""Per-project RBAC: the owner adds members with roles, and the role gates what they can do — an
operator may start/cancel runs and edit scope, a viewer may only watch, a non-member sees nothing.
Closes the review gap where any member could do anything."""
from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio


async def _user(app_ctx, email, role="operator"):
    from nabu_agent.auth.providers import hash_password
    from nabu_agent.db.models import User
    from nabu_agent.db.session import sessionmaker
    async with sessionmaker()() as db:
        db.add(User(email=email, display_name=email.split("@")[0], role=role, auth_source="local",
                    password_hash=hash_password("pw")))
        await db.commit()


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_role_gates_run_start_and_scope(client, app_ctx):
    app, _ = app_ctx
    # owner (the admin) sets up a project + scope, then adds an operator and a viewer
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Team"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5"})
    await _user(app_ctx, "op@corp.local", role="operator")     # global role; project role set below
    await _user(app_ctx, "viewer@corp.local", role="operator")
    assert (await client.post(f"/api/projects/{pid}/members",
                              json={"email": "op@corp.local", "role": "operator"})).status_code == 200
    assert (await client.post(f"/api/projects/{pid}/members",
                              json={"email": "viewer@corp.local", "role": "viewer"})).status_code == 200

    members = (await client.get(f"/api/projects/{pid}/members")).json()["members"]
    assert {m["role"] for m in members} == {"owner", "operator", "viewer"}

    # operator may start a run and edit scope
    op = _client(app)
    await op.post("/api/auth/login", json={"email": "op@corp.local", "password": "pw"})
    assert (await op.post(f"/api/projects/{pid}/runs",
                          json={"target": "10.10.10.5", "kind": "demo"})).status_code == 200
    assert (await op.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.6"})).status_code == 200
    await op.aclose()

    # viewer may watch but NOT start a run or edit scope
    vw = _client(app)
    await vw.post("/api/auth/login", json={"email": "viewer@corp.local", "password": "pw"})
    assert (await vw.post(f"/api/projects/{pid}/runs",
                          json={"target": "10.10.10.5", "kind": "demo"})).status_code == 403
    assert (await vw.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.7"})).status_code == 403
    assert (await vw.get(f"/api/projects/{pid}/report")).status_code == 200        # view is allowed
    assert (await vw.get(f"/api/projects/{pid}/activity")).status_code == 200
    await vw.aclose()

    # a non-member sees nothing (404, not 403 — existence isn't leaked)
    await _user(app_ctx, "stranger@corp.local", role="operator")
    st = _client(app)
    await st.post("/api/auth/login", json={"email": "stranger@corp.local", "password": "pw"})
    assert (await st.get(f"/api/projects/{pid}/report")).status_code == 404
    assert (await st.post(f"/api/projects/{pid}/runs",
                          json={"target": "10.10.10.5", "kind": "demo"})).status_code == 404
    await st.aclose()


async def test_only_owner_manages_members(client, app_ctx):
    app, _ = app_ctx
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Team2"})).json()["id"]
    await _user(app_ctx, "op2@corp.local", role="operator")
    await client.post(f"/api/projects/{pid}/members", json={"email": "op2@corp.local", "role": "operator"})

    # an operator cannot add members (owner-only)
    op = _client(app)
    await op.post("/api/auth/login", json={"email": "op2@corp.local", "password": "pw"})
    await _user(app_ctx, "op3@corp.local", role="operator")
    assert (await op.post(f"/api/projects/{pid}/members",
                          json={"email": "op3@corp.local", "role": "operator"})).status_code == 404
    await op.aclose()

    # owner can remove a member, but not the owner
    op2_id = (await client.get(f"/api/projects/{pid}/members")).json()["members"]
    op2_uid = next(m["user_id"] for m in op2_id if m["role"] == "operator")
    assert (await client.delete(f"/api/projects/{pid}/members/{op2_uid}")).status_code == 200
