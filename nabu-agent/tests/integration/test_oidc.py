"""OIDC/SSO login: providers reporting, login redirect, callback JIT-provisioning + session, and the
provision_user rules. The IdP is MOCKED (oidc.client()), so no live IdP/network is needed."""
from __future__ import annotations

import httpx
import pytest
from starlette.responses import RedirectResponse

pytestmark = pytest.mark.asyncio

_ISSUER = "https://idp.corp.example"


class _FakeOIDCClient:
    def __init__(self, claims):
        self._claims = claims

    async def authorize_redirect(self, request, redirect_uri):
        return RedirectResponse(f"{_ISSUER}/authorize?redirect_uri={redirect_uri}", status_code=302)

    async def authorize_access_token(self, request):
        return {"userinfo": self._claims}


def _configure_oidc(monkeypatch, claims):
    from nabu_agent.auth import oidc
    from nabu_agent.settings import get_settings
    monkeypatch.setenv("NABU_OIDC_ISSUER", _ISSUER)
    monkeypatch.setenv("NABU_OIDC_CLIENT_ID", "nabu")
    get_settings.cache_clear()
    monkeypatch.setattr(oidc, "client", lambda: _FakeOIDCClient(claims))
    return get_settings


async def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_providers_reports_oidc_when_configured(app_ctx, monkeypatch):
    app, _ = app_ctx
    _configure_oidc(monkeypatch, {})
    c = await _client(app)
    assert (await c.get("/api/auth/providers")).json()["oidc"] is True
    await c.aclose()
    from nabu_agent.settings import get_settings
    get_settings.cache_clear()


async def test_oidc_login_404_when_unconfigured(client):
    r = await client.get("/api/auth/oidc/login")
    assert r.status_code == 404


async def test_oidc_login_redirects_to_idp(app_ctx, monkeypatch):
    app, _ = app_ctx
    _configure_oidc(monkeypatch, {})
    c = await _client(app)
    r = await c.get("/api/auth/oidc/login")
    assert r.status_code == 302 and _ISSUER in r.headers["location"]
    await c.aclose()
    from nabu_agent.settings import get_settings
    get_settings.cache_clear()


async def test_oidc_callback_provisions_user_and_sets_session(app_ctx, monkeypatch):
    app, _ = app_ctx
    claims = {"iss": _ISSUER, "sub": "u-123", "email": "sso@corp.example", "name": "SSO User"}
    _configure_oidc(monkeypatch, claims)
    c = await _client(app)
    r = await c.get("/api/auth/oidc/callback")  # code/state validated by the (mocked) client
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert "nabu_session" in r.headers.get("set-cookie", "")
    # the cookie authenticates subsequent requests
    me = await c.get("/api/auth/me")
    assert me.status_code == 200 and me.json()["email"] == "sso@corp.example"
    await c.aclose()
    from nabu_agent.settings import get_settings
    get_settings.cache_clear()


async def test_provision_user_rules(app_ctx):
    from nabu_agent.auth.oidc import provision_user
    from nabu_agent.db.models import User
    from nabu_agent.db.session import sessionmaker
    from sqlalchemy import select
    # NOTE: app_ctx already seeded a local admin, so the first OIDC user is NOT the first user overall
    async with sessionmaker()() as db:
        u1 = await provision_user(db, issuer=_ISSUER, subject="a", email="a@corp.example", name="A")
        # idempotent by (issuer, subject)
        u1b = await provision_user(db, issuer=_ISSUER, subject="a", email="a@corp.example")
        assert u1.id == u1b.id
        # links an existing local account by email instead of duplicating
        local = User(email="link@corp.example", display_name="L", role="operator", auth_source="local")
        db.add(local); await db.commit(); local_id = local.id
        linked = await provision_user(db, issuer=_ISSUER, subject="b", email="link@corp.example")
        assert linked.id == local_id and linked.oidc_subject == "b"
        # count OIDC users
        oidc_users = (await db.execute(select(User).where(User.auth_source == "oidc"))).scalars().all()
        assert len(oidc_users) == 1  # only u1 is auth_source oidc; 'linked' stays local-linked
