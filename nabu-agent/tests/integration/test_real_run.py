"""Real-recon path (kind='scan') wiring test — the engine tools are MOCKED so we validate the
_run_real choreography (host → services → per-service enum agents → findings → report) + the live
event/node-state stream WITHOUT needing nmap or a live target. On the internal network with real
tools installed, the same path drives real recon through the shell.run chokepoint."""
from __future__ import annotations

import asyncio

import pytest

pytestmark = pytest.mark.asyncio


@pytest.fixture
def mock_engine(monkeypatch, tmp_path):
    import oscprecon.findings as ef
    from nabu_agent.engine import tools as etools
    from nabu_agent.engine import workspace as ews

    class _Prof:
        directory = tmp_path
        profile_name = "p"

    class _WS:
        def open_or_create(self):
            return _Prof()

    monkeypatch.setattr(ews, "workspace_for", lambda *a, **k: _WS())

    def _alive(profile, target=None, *, on_line=None, cancel=None):
        if on_line: on_line(f"[alive] {target} is up")
        return {"up": True, "count": 1, "hosts": [target]}

    def _scan(profile, scan_profile="default", *, resume=False, force=False, on_line=None, cancel=None):
        if on_line: on_line("[scan] 22/tcp open — OpenSSH"); on_line("[scan] 445/tcp open — Samba")
        return {"services": []}

    def _services(profile):
        return {"services": [
            {"port": 22, "proto": "tcp", "service": "ssh", "product": "OpenSSH 8.9"},
            {"port": 445, "proto": "tcp", "service": "smb", "product": "Samba 4.15"},
        ]}

    def _enum(profile, service, mode="full", *, port=0, as_user=None, on_line=None, cancel=None):
        if on_line: on_line(f"[enum] {service}:{port}")
        return {"service": service, "summary": [], "credentials_added": 0, "findings_added": 1}

    def _report(profile, *, persist=False):
        return {"markdown": "# report", "path": str(tmp_path / "report.md")}

    monkeypatch.setattr(etools, "check_alive", _alive)
    monkeypatch.setattr(etools, "run_scan", _scan)
    monkeypatch.setattr(etools, "list_discovered_services", _services)
    monkeypatch.setattr(etools, "enum_service", _enum)
    monkeypatch.setattr(etools, "generate_report", _report)
    monkeypatch.setattr(ef, "load_findings", lambda d: [
        {"kind": "smb-signing", "value": "SMB signing not required", "port": 445}])
    return True


async def test_real_run_choreography(client, mock_engine):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Real"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5"})
    rr = await client.post(f"/api/projects/{pid}/runs", json={"target": "10.10.10.5", "kind": "scan"})
    assert rr.status_code == 200, rr.text
    run_id = rr.json()["run_id"]

    types, node_ids, states = set(), set(), set()
    for _ in range(60):
        await asyncio.sleep(0.1)
        for e in (await client.get(f"/api/runs/{run_id}/events")).json()["events"]:
            types.add(e["type"])
            if e["data"].get("node_id"): node_ids.add(e["data"]["node_id"])
            if e["data"].get("node_state"): states.add(e["data"]["node_state"])
        if "done" in types:
            break
    assert "done" in types, f"real run did not finish; types={types}"
    # host, both services, both enum agents, the finding, and the report all appeared on the map
    assert "host-10.10.10.5" in node_ids
    assert {"svc-10.10.10.5-22-tcp", "svc-10.10.10.5-445-tcp"} <= node_ids
    assert {"agent-enum-10.10.10.5-22", "agent-enum-10.10.10.5-445"} <= node_ids  # host-scoped
    assert any(n.startswith("finding-") for n in node_ids)
    assert f"report-{run_id}" in node_ids
    assert {"active", "done"} <= states
    assert (await client.get(f"/api/runs/{run_id}")).json()["state"] in {"done", "partial"}
