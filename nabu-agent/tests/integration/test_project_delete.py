"""Project delete: removes DB rows + the on-disk workspace, refuses while a run is active, owner-only,
and the workspace delete is traversal-safe."""
from __future__ import annotations

import httpx
import pytest


async def _c(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_delete_removes_db_and_disk(app_ctx, monkeypatch, tmp_path):
    app, admin = app_ctx
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    c = await _c(app)
    await c.post("/api/auth/login", json=admin)
    pid = (await c.post("/api/projects", json={"display_name": "Del"})).json()["id"]
    await c.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5"})

    # simulate the on-disk Profile folder(s) for this project
    proj_dir = tmp_path / pid / "10.10.10.5"
    proj_dir.mkdir(parents=True)
    (proj_dir / "profile.json").write_text("{}")
    assert (tmp_path / pid).exists()

    r = await c.delete(f"/api/projects/{pid}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["deleted"] is True and body["workspace"]["removed"] is True
    assert not (tmp_path / pid).exists()                       # on-disk gone
    assert (await c.get(f"/api/projects/{pid}")).status_code == 404  # DB gone
    await c.aclose()


@pytest.mark.asyncio
async def test_delete_refused_while_run_active(app_ctx, monkeypatch, tmp_path):
    app, admin = app_ctx
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    from nabu_agent.db.models import Run
    from nabu_agent.db.session import sessionmaker
    c = await _c(app)
    await c.post("/api/auth/login", json=admin)
    pid = (await c.post("/api/projects", json={"display_name": "Busy"})).json()["id"]
    async with sessionmaker()() as db:
        db.add(Run(project_id=pid, kind="scan", target="10.0.0.1", state="scanning"))
        await db.commit()
    assert (await c.delete(f"/api/projects/{pid}")).status_code == 409  # active run blocks delete
    await c.aclose()


@pytest.mark.asyncio
async def test_delete_owner_only(app_ctx):
    app, admin = app_ctx
    a = await _c(app)
    await a.post("/api/auth/login", json=admin)
    pid = (await a.post("/api/projects", json={"display_name": "Owned"})).json()["id"]

    from nabu_agent.auth.providers import hash_password
    from nabu_agent.db.models import User
    from nabu_agent.db.session import sessionmaker
    async with sessionmaker()() as db:
        db.add(User(email="op2@x.io", display_name="op2", role="operator", auth_source="local",
                    password_hash=hash_password("pw")))
        await db.commit()
    b = await _c(app)
    await b.post("/api/auth/login", json={"email": "op2@x.io", "password": "pw"})
    assert (await b.delete(f"/api/projects/{pid}")).status_code == 404   # non-owner refused
    await a.aclose(); await b.aclose()


def test_workspace_delete_is_traversal_safe(tmp_path, monkeypatch):
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    from nabu_agent.engine.errors import InvalidTarget
    from nabu_agent.engine.workspace import delete_project_workspace
    for bad in ["../etc", "a/b", "..", "/etc"]:
        with pytest.raises(InvalidTarget):
            delete_project_workspace(bad)
    # a normal id that doesn't exist → no-op, not an error
    assert delete_project_workspace("does-not-exist")["removed"] is False
