"""Host tier — a CIDR run alive-sweeps, then fans out per-HOST recon (each host its own Profile +
host-scoped map subtree), bounded by the RunLimits host guardrails. Engine tools are MOCKED so we
validate the _resolve_hosts -> _recon_host choreography without nmap or live targets. This is the
piece that makes a real /24 possible (closes the docs/LOAD_TEST.md gap)."""
from __future__ import annotations

import asyncio

import pytest
from nabu_agent.services import runs as runs_svc

pytestmark = pytest.mark.asyncio


def _install(monkeypatch, tmp_path, live_hosts):
    """Patch the engine seams. check_alive on a CIDR returns ``live_hosts``; every host gets its own
    Profile directory so findings.json is per-host."""
    import oscprecon.findings as ef
    from nabu_agent.engine import tools as etools
    from nabu_agent.engine import workspace as ews

    def _slug(t: str) -> str:
        return "".join(c if (c.isalnum() or c in ".-") else "_" for c in t)

    class _Prof:
        def __init__(self, scope: str):
            self.directory = tmp_path / _slug(scope)
            self.directory.mkdir(parents=True, exist_ok=True)
            self.profile_name = scope

    class _WS:
        def __init__(self, scope):
            self.scope = scope

        def open_or_create(self):
            return _Prof(self.scope)

    monkeypatch.setattr(ews, "workspace_for", lambda pid, scope, *a, **k: _WS(scope))

    def _alive(profile, target=None, *, on_line=None, cancel=None):
        if target and "/" in target:            # CIDR sweep
            return {"up": True, "count": len(live_hosts), "hosts": list(live_hosts)}
        return {"up": True, "count": 1, "hosts": [target]}

    monkeypatch.setattr(etools, "check_alive", _alive)
    monkeypatch.setattr(etools, "run_scan",
                        lambda p, sp="default", **k: {"services": []})
    monkeypatch.setattr(etools, "list_discovered_services",
                        lambda p: {"services": [{"port": 445, "proto": "tcp", "service": "smb"}]})
    monkeypatch.setattr(etools, "enum_service",
                        lambda p, s, m="full", **k: {"service": s, "findings_added": 1})
    monkeypatch.setattr(etools, "generate_report",
                        lambda p, **k: {"markdown": "# r", "path": str(p.directory / "report.md")})
    monkeypatch.setattr(ef, "load_findings",
                        lambda d: [{"kind": "smb-signing", "value": "SMB signing off", "port": 445}])


async def _drive(client, cidr):
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "CIDR"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": cidr})
    rr = await client.post(f"/api/projects/{pid}/runs", json={"target": cidr, "kind": "scan"})
    assert rr.status_code == 200, rr.text
    run_id = rr.json()["run_id"]

    node_ids, types, lines = set(), set(), []
    for _ in range(200):
        await asyncio.sleep(0.1)
        # a fan-out above the approval threshold parks in awaiting_approval — auto-approve so the
        # deterministic choreography (clamp, per-host subtrees) can be asserted (the gate itself is
        # covered by test_approval_gate.py)
        for c in (await client.get(f"/api/runs/{run_id}/checkpoints")).json()["checkpoints"]:
            if c["status"] == "proposed" and c["kind"] == "hosts":
                await client.post(f"/api/runs/{run_id}/checkpoints/{c['id']}/approve")
        for e in (await client.get(f"/api/runs/{run_id}/events")).json()["events"]:
            types.add(e["type"])
            if e["data"].get("node_id"):
                node_ids.add(e["data"]["node_id"])
            if e["data"].get("line"):
                lines.append(e["data"]["line"])
        if "done" in types:
            break
    assert "done" in types, f"CIDR run did not finish; types={types}"
    return run_id, node_ids, lines


async def test_cidr_fans_out_per_host(client, monkeypatch, tmp_path):
    _install(monkeypatch, tmp_path, ["10.10.10.5", "10.10.10.6", "10.10.10.7"])
    _run_id, node_ids, lines = await _drive(client, "10.10.10.0/29")

    # each live host got its OWN host-scoped subtree — no cross-host node collisions
    for h in ("10.10.10.5", "10.10.10.6", "10.10.10.7"):
        assert f"host-{h}" in node_ids, f"missing host node for {h}"
        assert f"svc-{h}-445-tcp" in node_ids, f"missing svc node for {h}"
        assert f"agent-enum-{h}-445" in node_ids, f"missing enum agent for {h}"
        assert f"finding-{h}-445-0" in node_ids, f"missing finding for {h}"
    assert len([n for n in node_ids if n.startswith("host-")]) == 3
    assert any("3 host(s) up" in ln for ln in lines)


async def test_cidr_clamps_to_max_hosts(client, monkeypatch, tmp_path):
    monkeypatch.setattr(runs_svc, "_APPROVAL_POLL_S", 0.1)   # >32 hosts trips the approval gate
    from nabu_agent.orchestration.limits import RunLimits
    cap = RunLimits().max_hosts
    many = [f"10.10.10.{i}" for i in range(1, cap + 9)]     # cap + 8 live hosts
    _install(monkeypatch, tmp_path, many)
    _run_id, node_ids, lines = await _drive(client, "10.10.10.0/24")

    host_nodes = [n for n in node_ids if n.startswith("host-")]
    assert len(host_nodes) == cap, f"expected clamp to {cap}, got {len(host_nodes)}"
    assert any(f"capping to max_hosts={cap}" in ln for ln in lines)
