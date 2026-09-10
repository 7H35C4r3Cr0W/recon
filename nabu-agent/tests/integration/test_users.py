"""Global user provisioning (admin only): create/list/patch/deactivate local accounts, last-admin
lockout guard, and that a deactivated user can no longer log in."""
from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio


def _c(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_admin_creates_and_deactivates_users(client, app_ctx):
    app, _ = app_ctx
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})

    u = (await client.post("/api/users", json={"email": "newop@corp.local", "password": "pw123",
                                               "role": "operator"})).json()
    assert u["email"] == "newop@corp.local" and u["role"] == "operator" and "password_hash" not in u
    assert any(x["email"] == "newop@corp.local" for x in (await client.get("/api/users")).json()["users"])
    # duplicate email refused
    assert (await client.post("/api/users", json={"email": "newop@corp.local", "password": "x",
                                                  "role": "viewer"})).status_code == 409

    # the new user can log in...
    op = _c(app)
    assert (await op.post("/api/auth/login", json={"email": "newop@corp.local", "password": "pw123"})).status_code == 200
    # ...until an admin deactivates them (and their session is revoked)
    assert (await client.delete(f"/api/users/{u['id']}")).json() == {"deactivated": True}
    assert (await op.get("/api/auth/me")).status_code == 401                      # existing session revoked
    op2 = _c(app)
    assert (await op2.post("/api/auth/login", json={"email": "newop@corp.local", "password": "pw123"})).status_code == 401
    await op.aclose(); await op2.aclose()


async def test_cannot_lock_out_the_last_admin(client):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    me = (await client.get("/api/auth/me")).json()
    # demoting or deactivating the only admin is refused
    assert (await client.patch(f"/api/users/{me['id']}", json={"role": "operator"})).status_code == 409
    assert (await client.delete(f"/api/users/{me['id']}")).status_code == 409


async def test_user_endpoints_admin_only(client, app_ctx):
    from nabu_agent.auth.providers import hash_password
    from nabu_agent.db.models import User
    from nabu_agent.db.session import sessionmaker
    app, _ = app_ctx
    async with sessionmaker()() as db:
        db.add(User(email="op@c.io", display_name="op", role="operator", auth_source="local",
                    password_hash=hash_password("pw")))
        await db.commit()
    b = _c(app)
    await b.post("/api/auth/login", json={"email": "op@c.io", "password": "pw"})
    assert (await b.get("/api/users")).status_code == 403
    assert (await b.post("/api/users", json={"email": "x@c.io", "password": "p", "role": "viewer"})).status_code == 403
    await b.aclose()
