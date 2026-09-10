"""Per-service FAN-OUT: a real run enumerates multiple services CONCURRENTLY (several agent nodes
active at once on the live map), then joins. Engine tools are mocked; enum sleeps briefly and records
peak concurrency to prove the fan-out actually runs in parallel (not the old serial loop)."""
from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.asyncio


@pytest.fixture
def mock_multi_service(monkeypatch, tmp_path):
    import oscprecon.findings as ef
    from nabu_agent.engine import tools as etools
    from nabu_agent.engine import workspace as ews

    prof = SimpleNamespace(directory=tmp_path, profile_name="p",
                           target=SimpleNamespace(ip="10.10.10.5", hostname=None), discovered_services=[])
    monkeypatch.setattr(ews, "workspace_for", lambda *a, **k: SimpleNamespace(open_or_create=lambda: prof))
    monkeypatch.setattr(etools, "check_alive", lambda p, t=None, **k: {"up": True})
    monkeypatch.setattr(etools, "run_scan", lambda p, sp="default", **k: {"services": []})
    monkeypatch.setattr(etools, "list_discovered_services", lambda p: {"services": [
        {"port": 22, "proto": "tcp", "service": "ssh"}, {"port": 80, "proto": "tcp", "service": "http"},
        {"port": 445, "proto": "tcp", "service": "smb"}, {"port": 3306, "proto": "tcp", "service": "mysql"}]})
    monkeypatch.setattr(etools, "generate_report", lambda p, **k: {"markdown": "# r"})
    monkeypatch.setattr(ef, "load_findings", lambda d: [])

    state = {"cur": 0, "peak": 0, "lock": threading.Lock()}

    def _enum(p, service, mode="full", **k):
        with state["lock"]:
            state["cur"] += 1
            state["peak"] = max(state["peak"], state["cur"])
        time.sleep(0.2)
        with state["lock"]:
            state["cur"] -= 1
        return {"service": service, "summary": [], "credentials_added": 0, "findings_added": 0}
    monkeypatch.setattr(etools, "enum_service", _enum)
    return state


async def test_services_enumerated_concurrently(client, mock_multi_service):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Fan"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5"})
    run_id = (await client.post(f"/api/projects/{pid}/runs", json={"target": "10.10.10.5", "kind": "scan"})).json()["run_id"]

    node_ids, types = set(), set()
    for _ in range(80):
        await asyncio.sleep(0.1)
        for e in (await client.get(f"/api/runs/{run_id}/events")).json()["events"]:
            types.add(e["type"])
            if e["data"].get("node_id"): node_ids.add(e["data"]["node_id"])
        if "done" in types:
            break
    assert "done" in types
    # one agent node per service
    assert {"agent-enum-10.10.10.5-22", "agent-enum-10.10.10.5-80", "agent-enum-10.10.10.5-445", "agent-enum-10.10.10.5-3306"} <= node_ids  # host-scoped
    # the fan-out ran them concurrently (serial would peak at 1)
    assert mock_multi_service["peak"] >= 2, f"expected concurrent enum, peak={mock_multi_service['peak']}"
