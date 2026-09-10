"""Findings/services/graph/report views: degrade gracefully with no run, and pass engine data through."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def _setup(client):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Views"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5", "is_entry": True})
    return pid


async def test_views_empty_before_any_run(client):
    pid = await _setup(client)
    assert (await client.get(f"/api/projects/{pid}/findings")).json() == {"findings": []}
    assert (await client.get(f"/api/projects/{pid}/services")).json() == {"services": []}
    assert (await client.get(f"/api/projects/{pid}/graph")).json() == {"nodes": [], "edges": []}
    md = (await client.get(f"/api/projects/{pid}/report")).json()["markdown"]
    assert "No report" in md or "No recon" in md  # placeholder until the first run creates the Profile


async def test_views_pass_engine_data_through(client, monkeypatch):
    from nabu_agent.engine import gateway
    monkeypatch.setattr(gateway, "list_findings", lambda pid, scope, host: [
        {"value": "SMB signing not required", "port": 445, "_category": "exposure"}])
    monkeypatch.setattr(gateway, "list_services", lambda pid, scope, host: [
        {"port": 445, "proto": "tcp", "service": "smb"}])
    monkeypatch.setattr(gateway, "render_report", lambda pid, scope, host: "# Recon report\n- 445/smb")
    pid = await _setup(client)
    assert (await client.get(f"/api/projects/{pid}/findings")).json()["findings"][0]["port"] == 445
    assert (await client.get(f"/api/projects/{pid}/services")).json()["services"][0]["service"] == "smb"
    assert "Recon report" in (await client.get(f"/api/projects/{pid}/report")).json()["markdown"]
