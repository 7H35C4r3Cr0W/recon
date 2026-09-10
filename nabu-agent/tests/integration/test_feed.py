"""Activity feed: lists the caller's recent runs across their projects with an unread/attention count;
a non-member's feed excludes another user's runs."""
from __future__ import annotations

import asyncio

import httpx
import pytest

pytestmark = pytest.mark.asyncio


async def _c(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def _mk_user(email, pw):
    from nabu_agent.auth.providers import hash_password
    from nabu_agent.db.models import User
    from nabu_agent.db.session import sessionmaker
    async with sessionmaker()() as db:
        db.add(User(email=email, display_name=email, role="operator", auth_source="local",
                    password_hash=hash_password(pw)))
        await db.commit()


async def test_feed_lists_own_runs_and_isolates_others(app_ctx):
    app, admin = app_ctx
    a = await _c(app)
    await a.post("/api/auth/login", json=admin)
    pid = (await a.post("/api/projects", json={"display_name": "Feed Proj"})).json()["id"]
    await a.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5"})
    run_id = (await a.post(f"/api/projects/{pid}/runs", json={"target": "10.10.10.5", "kind": "demo"})).json()["run_id"]

    feed = (await a.get("/api/feed")).json()
    assert any(i["run_id"] == run_id and i["project"] == "Feed Proj" for i in feed["items"])
    assert feed["unread_count"] >= 1  # the run is live/attention

    # a different, non-member user sees an empty feed
    await _mk_user("b@x.io", "pw")
    b = await _c(app)
    await b.post("/api/auth/login", json={"email": "b@x.io", "password": "pw"})
    bf = (await b.get("/api/feed")).json()
    assert bf["items"] == [] and bf["unread_count"] == 0

    # let the demo finish; the run stays in the feed (terminal)
    for _ in range(120):
        await asyncio.sleep(0.1)
        if (await a.get(f"/api/runs/{run_id}")).json()["state"] in {"done", "partial", "failed"}:
            break
    feed2 = (await a.get("/api/feed")).json()
    assert any(i["run_id"] == run_id for i in feed2["items"])
    await a.aclose(); await b.aclose()
