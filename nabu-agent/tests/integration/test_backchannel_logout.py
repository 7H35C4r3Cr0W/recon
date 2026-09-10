"""OIDC back-channel logout: a per-user session index lets us revoke ALL of a user's sessions when
the IdP POSTs a (validated) logout token. Token validation is mocked (no live IdP/JWKS)."""
from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio

_ISS = "https://idp.corp.example"


async def test_destroy_user_sessions_revokes_all(app_ctx):
    from nabu_agent.auth import sessions
    s1 = await sessions.create_session("user-1")
    s2 = await sessions.create_session("user-1")
    assert await sessions.resolve_session(s1) == "user-1"
    assert await sessions.resolve_session(s2) == "user-1"
    n = await sessions.destroy_user_sessions("user-1")
    assert n == 2
    assert await sessions.resolve_session(s1) is None
    assert await sessions.resolve_session(s2) is None


def _configure(monkeypatch):
    from nabu_agent.settings import get_settings
    monkeypatch.setenv("NABU_OIDC_ISSUER", _ISS)
    monkeypatch.setenv("NABU_OIDC_CLIENT_ID", "nabu")
    get_settings.cache_clear()


async def test_backchannel_logout_revokes_and_bad_token_400(app_ctx, monkeypatch):
    app, _ = app_ctx
    from nabu_agent.auth import oidc, sessions
    from nabu_agent.db.models import User
    from nabu_agent.db.session import sessionmaker

    _configure(monkeypatch)
    async with sessionmaker()() as db:
        u = User(email="sso@corp.example", display_name="sso", role="operator", auth_source="oidc",
                 oidc_issuer=_ISS, oidc_subject="sub-9")
        db.add(u); await db.commit(); uid = u.id
    sid = await sessions.create_session(uid)
    assert await sessions.resolve_session(sid) == uid

    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")

    # valid logout token (validation mocked) → the user's session is revoked
    async def _ok(token):
        return {"iss": _ISS, "sub": "sub-9", "events": {oidc._LOGOUT_EVENT: {}}}
    monkeypatch.setattr(oidc, "validate_logout_token", _ok)
    r = await c.post("/api/auth/oidc/backchannel-logout", data={"logout_token": "x"})
    assert r.status_code == 200, r.text
    assert r.json()["revoked"] == 1
    assert r.headers.get("cache-control") == "no-store"
    assert await sessions.resolve_session(sid) is None      # session killed

    # a bad token → 400
    async def _bad(token):
        raise ValueError("bad signature")
    monkeypatch.setattr(oidc, "validate_logout_token", _bad)
    assert (await c.post("/api/auth/oidc/backchannel-logout", data={"logout_token": "x"})).status_code == 400

    # missing token → 400
    assert (await c.post("/api/auth/oidc/backchannel-logout", data={})).status_code == 400
    await c.aclose()
    from nabu_agent.settings import get_settings
    get_settings.cache_clear()


async def test_backchannel_404_when_unconfigured(client):
    r = await client.post("/api/auth/oidc/backchannel-logout", data={"logout_token": "x"})
    assert r.status_code == 404
