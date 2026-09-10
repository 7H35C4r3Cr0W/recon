"""Host-count approval gate — a fan-out to more than RunLimits.approval_required_above_hosts live
hosts PARKS the run in awaiting_approval with a proposed Checkpoint, and does NOT fan out until a
human approves (or is rejected / times out). Engine tools are mocked."""
from __future__ import annotations

import asyncio

import pytest
from nabu_agent.services import runs as runs_svc

pytestmark = pytest.mark.asyncio

HOSTS = [f"10.10.10.{i}" for i in range(1, 21)]   # 20 live hosts > threshold (16)


def _install(monkeypatch, tmp_path, live_hosts):
    from types import SimpleNamespace

    import oscprecon.findings as ef
    from nabu_agent.engine import tools as etools
    from nabu_agent.engine import workspace as ews

    prof = SimpleNamespace(directory=tmp_path, profile_name="p",
                           target=SimpleNamespace(ip="10.10.10.5", hostname=None), discovered_services=[])
    monkeypatch.setattr(ews, "workspace_for", lambda *a, **k: SimpleNamespace(open_or_create=lambda: prof))

    def _alive(p, t=None, **k):
        if t and "/" in t:
            return {"up": True, "count": len(live_hosts), "hosts": list(live_hosts)}
        return {"up": True, "count": 1, "hosts": [t]}
    monkeypatch.setattr(etools, "check_alive", _alive)
    monkeypatch.setattr(etools, "run_scan", lambda p, sp="default", **k: {"services": []})
    monkeypatch.setattr(etools, "list_discovered_services",
                        lambda p: {"services": [{"port": 445, "proto": "tcp", "service": "smb"}]})
    monkeypatch.setattr(etools, "enum_service", lambda p, s, m="full", **k: {"service": s, "findings_added": 0})
    monkeypatch.setattr(etools, "generate_report", lambda p, **k: {"markdown": "# r"})
    monkeypatch.setattr(ef, "load_findings", lambda d: [])


async def _start_cidr_run(client):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Gate"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.0/24"})
    rr = await client.post(f"/api/projects/{pid}/runs", json={"target": "10.10.10.0/24", "kind": "scan"})
    assert rr.status_code == 200, rr.text
    return rr.json()["run_id"]


async def _await_checkpoint(client, run_id):
    """Wait until the run parks in awaiting_approval with a proposed 'hosts' checkpoint; return its id."""
    for _ in range(150):
        await asyncio.sleep(0.1)
        state = (await client.get(f"/api/runs/{run_id}")).json()["state"]
        if state == "awaiting_approval":
            cps = (await client.get(f"/api/runs/{run_id}/checkpoints")).json()["checkpoints"]
            proposed = [c for c in cps if c["status"] == "proposed" and c["kind"] == "hosts"]
            if proposed:
                return proposed[0]["id"]
    return None


def _host_nodes(events):
    return {e["data"]["node_id"] for e in events
            if str(e["data"].get("node_id", "")).startswith("host-10.10.10.")}


async def test_large_fanout_parks_then_proceeds_on_approval(client, monkeypatch, tmp_path):
    monkeypatch.setattr(runs_svc, "_APPROVAL_POLL_S", 0.1)
    _install(monkeypatch, tmp_path, HOSTS)
    run_id = await _start_cidr_run(client)

    cp_id = await _await_checkpoint(client, run_id)
    assert cp_id, "run never parked in awaiting_approval"

    # the gate held the fan-out: no per-host nodes yet, and an approval.required event was emitted
    evs = (await client.get(f"/api/runs/{run_id}/events")).json()["events"]
    assert not _host_nodes(evs), "hosts fanned out BEFORE approval"
    assert any(e["type"] == "approval.required" for e in evs)

    r = await client.post(f"/api/runs/{run_id}/checkpoints/{cp_id}/approve")
    assert r.status_code == 200, r.text

    types: set[str] = set()
    for _ in range(200):
        await asyncio.sleep(0.1)
        evs = (await client.get(f"/api/runs/{run_id}/events")).json()["events"]
        types = {e["type"] for e in evs}
        if "done" in types:
            break
    assert "done" in types, f"run did not finish after approval; types={types}"
    assert _host_nodes(evs), "no host fan-out after approval"
    assert (await client.get(f"/api/runs/{run_id}")).json()["state"] in {"done", "partial"}


async def test_large_fanout_rejected_stops_run(client, monkeypatch, tmp_path):
    monkeypatch.setattr(runs_svc, "_APPROVAL_POLL_S", 0.1)
    _install(monkeypatch, tmp_path, HOSTS)
    run_id = await _start_cidr_run(client)

    cp_id = await _await_checkpoint(client, run_id)
    assert cp_id, "run never parked in awaiting_approval"

    r = await client.post(f"/api/runs/{run_id}/checkpoints/{cp_id}/reject")
    assert r.status_code == 200, r.text

    state = None
    for _ in range(150):
        await asyncio.sleep(0.1)
        state = (await client.get(f"/api/runs/{run_id}")).json()["state"]
        if state in {"done", "partial", "failed", "cancelled"}:
            break
    assert state == "cancelled", f"rejected run should be cancelled, got {state}"
    evs = (await client.get(f"/api/runs/{run_id}/events")).json()["events"]
    assert not _host_nodes(evs), "rejected run must not fan out"


async def test_no_decision_times_out_to_failed(client, monkeypatch, tmp_path):
    monkeypatch.setattr(runs_svc, "_APPROVAL_POLL_S", 0.1)
    monkeypatch.setattr(runs_svc, "_APPROVAL_TIMEOUT_S", 0.3)
    _install(monkeypatch, tmp_path, HOSTS)
    run_id = await _start_cidr_run(client)

    # never approve — the gate should time out and end the run failed
    state = None
    for _ in range(150):
        await asyncio.sleep(0.1)
        state = (await client.get(f"/api/runs/{run_id}")).json()["state"]
        if state in {"done", "partial", "failed", "cancelled"}:
            break
    assert state == "failed", f"un-approved run should time out to failed, got {state}"
    evs = (await client.get(f"/api/runs/{run_id}/events")).json()["events"]
    assert not _host_nodes(evs), "timed-out run must not fan out"


async def test_small_fanout_needs_no_approval(client, monkeypatch, tmp_path):
    monkeypatch.setattr(runs_svc, "_APPROVAL_POLL_S", 0.1)
    _install(monkeypatch, tmp_path, ["10.10.10.5", "10.10.10.6"])   # 2 hosts, under threshold
    run_id = await _start_cidr_run(client)

    types: set[str] = set()
    for _ in range(200):
        await asyncio.sleep(0.1)
        evs = (await client.get(f"/api/runs/{run_id}/events")).json()["events"]
        types = {e["type"] for e in evs}
        if "done" in types:
            break
    assert "done" in types
    assert not any(e["type"] == "approval.required" for e in evs), "small fan-out must not gate"
    cps = (await client.get(f"/api/runs/{run_id}/checkpoints")).json()["checkpoints"]
    assert cps == []
