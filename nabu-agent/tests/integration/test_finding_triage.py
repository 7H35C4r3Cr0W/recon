"""Findings triage overlay: an operator marks a finding reviewed/confirmed/dismissed with a note; it
merges into the findings list and survives (keyed by a stable finding hash). Viewers can't triage."""
from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio


async def test_triage_roundtrip(client, monkeypatch, tmp_path):
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    import oscprecon.findings as ef
    from nabu_agent.engine.workspace import workspace_for

    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Triage"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.50.5"})
    p = workspace_for(pid, "10.10.50.5").open_or_create()
    ef.add_findings(p.directory, [{"kind": "vuln", "value": "MS17-010", "port": 445}])

    rows = (await client.get(f"/api/projects/{pid}/findings")).json()["findings"]
    assert rows and rows[0]["triage"]["status"] == "open" and rows[0]["id"]
    fid = rows[0]["id"]

    r = await client.post(f"/api/projects/{pid}/findings/{fid}/triage",
                          json={"status": "confirmed", "note": "validated on the box"})
    assert r.status_code == 200 and r.json()["status"] == "confirmed"
    assert (await client.post(f"/api/projects/{pid}/findings/{fid}/triage",
                              json={"status": "bogus"})).status_code == 422

    rows2 = (await client.get(f"/api/projects/{pid}/findings")).json()["findings"]
    t = next(f["triage"] for f in rows2 if f["id"] == fid)
    assert t["status"] == "confirmed" and t["note"] == "validated on the box"


async def test_viewer_cannot_triage(client, app_ctx, monkeypatch, tmp_path):
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    from nabu_agent.auth.providers import hash_password
    from nabu_agent.db.models import User
    from nabu_agent.db.session import sessionmaker
    app, _ = app_ctx
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Triage2"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.50.5"})
    async with sessionmaker()() as db:
        db.add(User(email="v@c.io", display_name="v", role="operator", auth_source="local",
                    password_hash=hash_password("pw")))
        await db.commit()
    await client.post(f"/api/projects/{pid}/members", json={"email": "v@c.io", "role": "viewer"})
    v = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    await v.post("/api/auth/login", json={"email": "v@c.io", "password": "pw"})
    assert (await v.get(f"/api/projects/{pid}/findings")).status_code == 200        # can read
    assert (await v.post(f"/api/projects/{pid}/findings/abc123/triage",
                         json={"status": "reviewed"})).status_code == 403           # cannot triage
    await v.aclose()
