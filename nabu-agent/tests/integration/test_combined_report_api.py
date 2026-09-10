"""GET /projects/{id}/report returns the COMBINED multi-host report when the project scope is a
CIDR (aggregating every per-host Profile), and the per-host report for a single host. Builds real
Profiles on disk under a temp workspace root, then reads back through the API."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_cidr_report_is_combined(client, monkeypatch, tmp_path):
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    import oscprecon.findings as ef
    from nabu_agent.engine.workspace import workspace_for

    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Range"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.0/29"})

    # simulate what a multi-host run leaves on disk: one Profile + findings per live host
    p5 = workspace_for(pid, "10.10.10.5").open_or_create()
    p6 = workspace_for(pid, "10.10.10.6").open_or_create()
    ef.add_findings(p5.directory, [
        {"kind": "vuln", "value": "MS17-010 SMB RCE", "port": 445, "severity": "vulnerable"}])
    ef.add_findings(p6.directory, [
        {"kind": "world-readable", "value": "IPC$ anon readable", "port": 445, "severity": "exposure"}])

    r = await client.get(f"/api/projects/{pid}/report")
    assert r.status_code == 200, r.text
    md = r.json()["markdown"]
    assert "# Combined Recon Report" in md
    assert "## Host: 10.10.10.5" in md and "## Host: 10.10.10.6" in md
    assert "MS17-010 SMB RCE" in md and "IPC$ anon readable" in md
    assert "## Suggested next steps" in md


async def test_cidr_report_before_any_run_is_friendly(client, monkeypatch, tmp_path):
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Range2"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.20.0/29"})
    r = await client.get(f"/api/projects/{pid}/report")
    assert r.status_code == 200, r.text
    assert "No report yet" in r.json()["markdown"]


async def test_cidr_findings_are_aggregated_across_hosts(client, monkeypatch, tmp_path):
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    import oscprecon.findings as ef
    from nabu_agent.engine.workspace import workspace_for

    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "RangeF"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.30.0/29"})
    a = workspace_for(pid, "10.10.30.5").open_or_create()
    b = workspace_for(pid, "10.10.30.6").open_or_create()
    ef.add_findings(a.directory, [{"kind": "vuln", "value": "on-a", "port": 445, "severity": "vulnerable"}])
    ef.add_findings(b.directory, [{"kind": "world-readable", "value": "on-b", "port": 445, "severity": "exposure"}])

    rows = (await client.get(f"/api/projects/{pid}/findings")).json()["findings"]
    vals = {r["value"] for r in rows}
    assert {"on-a", "on-b"} <= vals                         # both hosts' findings aggregated
    hosts = {r.get("_host") for r in rows}
    assert {"10.10.30.5", "10.10.30.6"} <= hosts            # each tagged with its host
    assert rows[0]["_category"] == "vulnerable"             # sorted strongest-first


async def test_project_export_bundle(client, monkeypatch, tmp_path):
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    import oscprecon.findings as ef
    from nabu_agent.engine.workspace import workspace_for

    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Exp"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.40.0/29"})
    a = workspace_for(pid, "10.10.40.5").open_or_create()
    ef.add_findings(a.directory, [{"kind": "vuln", "value": "MS17-010", "port": 445, "severity": "vulnerable"}])

    b = (await client.post(f"/api/projects/{pid}/export")).json()
    assert b["scope"] == "10.10.40.0/29" and b["generated_at"]
    assert "# Combined Recon Report" in b["report_md"]
    assert any(f["value"] == "MS17-010" for f in b["findings"])
    assert "credentials" not in b            # the vault never leaves via export
