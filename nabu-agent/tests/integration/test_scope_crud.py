"""Scope targets are full CRUD now — add, list, and REMOVE (removal was a 501 stub)."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_scope_add_list_remove(client):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Scoped"})).json()["id"]
    tid = (await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.6"})

    assert len((await client.get(f"/api/projects/{pid}/scope")).json()["scope"]) == 2
    r = await client.delete(f"/api/projects/{pid}/scope/{tid}")
    assert r.status_code == 200 and r.json()["target"] == "10.10.10.5"
    left = (await client.get(f"/api/projects/{pid}/scope")).json()["scope"]
    assert [s["target"] for s in left] == ["10.10.10.6"]
    assert (await client.delete(f"/api/projects/{pid}/scope/{tid}")).status_code == 404  # already gone
