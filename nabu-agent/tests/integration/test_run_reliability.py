"""Reliability: a run that ERRORS still emits exactly one terminal DONE (so the live WS never hangs)
and lands in a terminal state. Covers the fix for the 'DONE never published on the failure path' hang."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.asyncio


async def test_failed_run_still_emits_done(client, monkeypatch, tmp_path):
    from nabu_agent.engine import tools as etools
    from nabu_agent.engine import workspace as ews

    prof = SimpleNamespace(directory=tmp_path, profile_name="p",
                           target=SimpleNamespace(ip="10.10.10.5", hostname=None), discovered_services=[])
    monkeypatch.setattr(ews, "workspace_for", lambda *a, **k: SimpleNamespace(open_or_create=lambda: prof))
    monkeypatch.setattr(etools, "check_alive", lambda p, t=None, **k: {"up": True})

    def _boom(*a, **k):
        raise RuntimeError("nmap exploded")
    monkeypatch.setattr(etools, "run_scan", _boom)  # force the driver to raise mid-run

    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Fail"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5"})
    run_id = (await client.post(f"/api/projects/{pid}/runs", json={"target": "10.10.10.5", "kind": "scan"})).json()["run_id"]

    done_states, done_count = [], 0
    for _ in range(50):
        await asyncio.sleep(0.1)
        evs = (await client.get(f"/api/runs/{run_id}/events")).json()["events"]
        dones = [e for e in evs if e["type"] == "done"]
        done_count = len(dones)
        done_states = [d["data"].get("state") for d in dones]
        if dones:
            break
    assert done_count == 1, f"expected exactly one terminal DONE, got {done_count}"
    assert done_states == ["failed"]
    # an ERROR event was surfaced and the run row is terminal
    assert any(e["type"] == "error" for e in (await client.get(f"/api/runs/{run_id}/events")).json()["events"])
    assert (await client.get(f"/api/runs/{run_id}")).json()["state"] == "failed"
