"""Phase A of the spray/exploit execution gate — the human-driven path.

An operator PROPOSES an executable catalog action; a human APPROVES it behind the double gate
(platform switch + per-project toggle + approval, plus exploit_confirmed / a chosen credential);
the system then re-derives the command from the catalog by action_id and runs it through the one
gated door. These tests prove: viewers can't propose; every gate is enforced at approve time; the
executed command is the catalog's (never a client-supplied string); and the door is handed a
genuinely-approved checkpoint.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

pytestmark = pytest.mark.asyncio

# A controlled catalog action so the test doesn't depend on the engine catalog's contents.
_ACTION = {"id": "smb-cme-exec", "title": "CME exec", "category": "exploit", "tool": "crackmapexec",
           "command": "crackmapexec smb 10.10.60.7 -u admin -p pw -x whoami", "unfilled": [],
           "ports": [445], "runs_on": "attacker", "executable": True, "suggested": True,
           "score": 9, "why": "test", "source": "test"}


def _install(monkeypatch, door_calls: list):
    """Fake the catalog (return our one executable action) + the gated door (capture, don't run)."""
    from nabu_agent.engine import shell_gateway as sg
    from nabu_agent.engine import tools as etools

    monkeypatch.setattr(etools, "catalog_actions_for",
                        lambda service, evidence, **k: {"service": service, "label": service,
                                                        "note": "", "actions": [dict(_ACTION)]})

    def _fake_door(checkpoint, profile, shell_line, output_file, **k):
        door_calls.append({"shell_line": shell_line, "status": checkpoint.status,
                           "approved_by": checkpoint.approved_by, "kind": checkpoint.kind,
                           "target": checkpoint.target, "exploit_confirmed": checkpoint.exploit_confirmed})
        return {"exit_code": 0, "blocked": None, "missing_tool": None, "stdout_tail": "root\n"}

    monkeypatch.setattr(sg, "execute_gated_action", _fake_door)


async def _seed(client, monkeypatch, tmp_path, target="10.10.60.7"):
    """Admin project + scope + on-disk profile + a finished run to hang the proposal on."""
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    from nabu_agent.db.models import Run
    from nabu_agent.db.session import sessionmaker
    from nabu_agent.engine.workspace import workspace_for

    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Attack"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": target})
    workspace_for(pid, target).open_or_create()             # the profile the executor will open()
    async with sessionmaker()() as db:
        run = Run(project_id=pid, kind="scan", target=target, state="done")
        db.add(run)
        await db.commit()
        run_id = run.id
    return pid, run_id, target


async def _poll_status(client, run_id, cp_id, want, tries=50):
    for _ in range(tries):
        cps = (await client.get(f"/api/runs/{run_id}/checkpoints")).json()["checkpoints"]
        cp = next((c for c in cps if c["id"] == cp_id), None)
        if cp and cp["status"] == want:
            return cp
        await asyncio.sleep(0.05)
    return None


async def test_exploit_happy_path_reuses_catalog_command(client, monkeypatch, tmp_path):
    door: list = []
    _install(monkeypatch, door)
    from nabu_agent.settings import get_settings
    monkeypatch.setattr(get_settings(), "exploit_enabled", True)     # platform switch ON

    pid, run_id, target = await _seed(client, monkeypatch, tmp_path)

    # 1. propose — returns the truthful, server-derived command preview
    r = await client.post(f"/api/runs/{run_id}/attack-proposals",
                          json={"kind": "exploit", "target": target, "service": "smb", "action_id": _ACTION["id"]})
    assert r.status_code == 200, r.text
    cp_id = r.json()["checkpoint_id"]
    assert r.json()["command"] == _ACTION["command"]

    # 2. approve refused until the PROJECT toggle is on
    assert (await client.post(f"/api/runs/{run_id}/checkpoints/{cp_id}/approve",
                              json={"exploit_confirmed": True})).status_code == 409
    await client.patch(f"/api/projects/{pid}/settings", json={"exploit_enabled": True})

    # 3. approve refused without the explicit exploit confirmation
    assert (await client.post(f"/api/runs/{run_id}/checkpoints/{cp_id}/approve",
                              json={"exploit_confirmed": False})).status_code == 422

    # 4. approve with the confirmation → enqueues execution
    ok = await client.post(f"/api/runs/{run_id}/checkpoints/{cp_id}/approve",
                           json={"exploit_confirmed": True})
    assert ok.status_code == 200 and ok.json()["enqueued"] is True

    # 5. it executes through the one door with the CATALOG command (never a client string)
    cp = await _poll_status(client, run_id, cp_id, "executed")
    assert cp is not None, "checkpoint never reached 'executed'"
    assert len(door) == 1
    assert door[0]["shell_line"] == _ACTION["command"]        # re-derived from action_id, not supplied
    assert door[0]["status"] == "approved" and door[0]["approved_by"]   # door got a real approval
    assert door[0]["kind"] == "exploit" and door[0]["exploit_confirmed"] is True


async def test_platform_switch_off_blocks_approval(client, monkeypatch, tmp_path):
    door: list = []
    _install(monkeypatch, door)
    from nabu_agent.settings import get_settings
    monkeypatch.setattr(get_settings(), "exploit_enabled", False)   # platform switch OFF (default)

    pid, run_id, target = await _seed(client, monkeypatch, tmp_path)
    await client.patch(f"/api/projects/{pid}/settings", json={"exploit_enabled": True})  # project on, platform off
    cp_id = (await client.post(f"/api/runs/{run_id}/attack-proposals",
             json={"kind": "exploit", "target": target, "service": "smb", "action_id": _ACTION["id"]})).json()["checkpoint_id"]

    r = await client.post(f"/api/runs/{run_id}/checkpoints/{cp_id}/approve", json={"exploit_confirmed": True})
    assert r.status_code == 409 and "platform-wide" in r.json()["detail"]
    assert door == []                                               # nothing ran


async def test_spray_requires_a_credential(client, monkeypatch, tmp_path):
    door: list = []
    _install(monkeypatch, door)
    from nabu_agent.settings import get_settings
    monkeypatch.setattr(get_settings(), "spray_enabled", True)

    pid, run_id, target = await _seed(client, monkeypatch, tmp_path)
    await client.patch(f"/api/projects/{pid}/settings", json={"spray_enabled": True})
    cp_id = (await client.post(f"/api/runs/{run_id}/attack-proposals",
             json={"kind": "spray", "target": target, "service": "smb", "action_id": _ACTION["id"]})).json()["checkpoint_id"]

    # no credential → refused
    assert (await client.post(f"/api/runs/{run_id}/checkpoints/{cp_id}/approve", json={})).status_code == 422
    # with a credential_ref → approved + enqueued
    ok = await client.post(f"/api/runs/{run_id}/checkpoints/{cp_id}/approve",
                           json={"credential_ref": "cred-abc"})
    assert ok.status_code == 200
    assert await _poll_status(client, run_id, cp_id, "executed") is not None
    assert door and door[0]["shell_line"] == _ACTION["command"]


async def test_bad_action_id_is_not_proposable(client, monkeypatch, tmp_path):
    _install(monkeypatch, [])
    pid, run_id, target = await _seed(client, monkeypatch, tmp_path)
    r = await client.post(f"/api/runs/{run_id}/attack-proposals",
                          json={"kind": "exploit", "target": target, "service": "smb", "action_id": "does-not-exist"})
    assert r.status_code == 422 and "not proposable" in r.json()["detail"]


async def test_out_of_scope_target_refused(client, monkeypatch, tmp_path):
    _install(monkeypatch, [])
    pid, run_id, target = await _seed(client, monkeypatch, tmp_path)
    r = await client.post(f"/api/runs/{run_id}/attack-proposals",
                          json={"kind": "exploit", "target": "8.8.8.8", "service": "smb", "action_id": _ACTION["id"]})
    assert r.status_code == 403       # ScopeViolation → 403 envelope


async def test_viewer_cannot_propose(client, app_ctx, monkeypatch, tmp_path):
    _install(monkeypatch, [])
    from nabu_agent.auth.providers import hash_password
    from nabu_agent.db.models import User
    from nabu_agent.db.session import sessionmaker
    app, _ = app_ctx
    pid, run_id, target = await _seed(client, monkeypatch, tmp_path)
    async with sessionmaker()() as db:
        db.add(User(email="viewer@c.io", display_name="v", role="operator", auth_source="local",
                    password_hash=hash_password("pw")))
        await db.commit()
    await client.post(f"/api/projects/{pid}/members", json={"email": "viewer@c.io", "role": "viewer"})
    v = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    await v.post("/api/auth/login", json={"email": "viewer@c.io", "password": "pw"})
    r = await v.post(f"/api/runs/{run_id}/attack-proposals",
                     json={"kind": "exploit", "target": target, "service": "smb", "action_id": _ACTION["id"]})
    assert r.status_code == 403
    await v.aclose()
