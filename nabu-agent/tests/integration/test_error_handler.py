"""Unhandled exceptions return the standard error envelope (500) + are logged (not a bare trace).
Uses raise_app_exceptions=False so the transport surfaces the 500 response the client would receive
in production (uvicorn returns the handler's response and logs the re-raise)."""
from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio


async def test_unhandled_exception_returns_envelope(app_ctx):
    from nabu_agent.engine import gateway

    app, admin = app_ctx

    def _boom(*a, **k):
        raise ValueError("kaboom")

    # patch after building the app
    import pytest as _pytest
    mp = _pytest.MonkeyPatch()
    mp.setattr(gateway, "render_report", _boom)
    try:
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            await c.post("/api/auth/login", json=admin)
            pid = (await c.post("/api/projects", json={"display_name": "Err"})).json()["id"]
            await c.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5"})
            r = await c.get(f"/api/projects/{pid}/report")
            assert r.status_code == 500, r.text
            body = r.json()
            assert body["code"] == "internal_error"
            assert "message" in body and "request_id" in body
    finally:
        mp.undo()
