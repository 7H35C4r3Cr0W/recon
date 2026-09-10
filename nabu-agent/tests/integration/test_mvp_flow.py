"""MVP thin-slice integration: login → create project → add scope → start a demo run → live events
stream (the BloodHound-map feed) → out-of-scope is refused. No docker/Postgres/Redis (sqlite+fakeredis)."""
from __future__ import annotations

import asyncio

import pytest

pytestmark = pytest.mark.asyncio


async def _login(client, creds):
    r = await client.post("/api/auth/login", json=creds)
    assert r.status_code == 200, r.text
    return r


async def test_health_ready(client):
    r = await client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


async def test_full_flow(client, app_ctx):
    _app, creds = app_ctx
    # unauthenticated is refused
    assert (await client.get("/api/auth/me")).status_code == 401
    # login sets the session cookie (carried by the client jar)
    await _login(client, creds)
    me = await client.get("/api/auth/me")
    assert me.status_code == 200 and me.json()["role"] == "admin"

    # create a project
    pr = await client.post("/api/projects", json={"display_name": "Engagement A"})
    assert pr.status_code == 200, pr.text
    pid = pr.json()["id"]

    # starting a run with no scope is refused (422)
    assert (await client.post(f"/api/projects/{pid}/runs", json={"target": "10.10.10.5"})).status_code == 422

    # add authorized scope
    sc = await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.0/24", "is_entry": True})
    assert sc.status_code == 200, sc.text

    # out-of-scope target is refused (the scope-lock)
    oos = await client.post(f"/api/projects/{pid}/runs", json={"target": "192.168.1.1"})
    assert oos.status_code == 403

    # in-scope demo run starts
    rr = await client.post(f"/api/projects/{pid}/runs", json={"target": "10.10.10.5", "kind": "demo"})
    assert rr.status_code == 200, rr.text
    run_id = rr.json()["run_id"]

    # the demo choreography streams events; poll the persisted feed until 'done'
    types = set()
    node_states = set()
    for _ in range(60):
        await asyncio.sleep(0.2)
        ev = (await client.get(f"/api/runs/{run_id}/events")).json()["events"]
        for e in ev:
            types.add(e["type"])
            if e["data"].get("node_state"):
                node_states.add(e["data"]["node_state"])
        if "done" in types:
            break
    assert "done" in types, f"run did not finish; saw {types}"
    assert {"run.status", "task.created", "task.updated", "log.line", "finding.added"} <= types
    # the live-map colours were emitted (agents in motion)
    assert {"active", "done"} <= node_states
    # run row reached a terminal state
    assert (await client.get(f"/api/runs/{run_id}")).json()["state"] == "done"
