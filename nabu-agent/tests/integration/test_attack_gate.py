"""The spray/exploit execution gate — Phase A (human-driven path) + Phase C (usable + safe).

Phase A: an operator PROPOSES an executable catalog action; a human APPROVES it behind the double
gate (platform switch + per-project toggle + approval, plus exploit_confirmed / a chosen credential);
the system re-derives the command from the catalog by action_id and runs it through the one gated
door. Phase C: a chosen vault credential + operator params fill the command's placeholders; the
secret is injected only at execute time (preview is redacted); a per-run attack cap; the used
credential's tested_against is recorded.

These tests prove: viewers can't propose; every gate is enforced at approve time; the executed
command is the catalog's (never a client string); the injected secret reaches only the door (never
the preview or the event stream); missing placeholders are reported; the cap holds.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import pytest

pytestmark = pytest.mark.asyncio


def _install(monkeypatch, door_calls: list, template: str = "crackmapexec smb {target}"):
    """Fake the catalog with ONE executable action whose command is filled from the passed evidence
    values using the REAL engine fill/missing helpers (so credential + param injection is exercised
    faithfully), and the gated door (capture, don't run)."""
    from nabu_agent.engine import shell_gateway as sg
    from nabu_agent.engine import tools as etools
    from oscprecon.exploit import base as exb

    def _cat(service, evidence, **k):
        values = {kk: str(vv) for kk, vv in (evidence.get("values") or {}).items()}
        return {"service": service, "label": service, "note": "", "actions": [{
            "id": "smb-cme-exec", "title": "CME exec", "category": "exploit",
            "command": exb.fill_template(template, values),
            "unfilled": exb.missing_placeholders(template, values),
            "tool": "crackmapexec", "ports": [445], "runs_on": "attacker",
            "executable": True, "suggested": True, "score": 9, "why": "t", "source": "t"}]}

    monkeypatch.setattr(etools, "catalog_actions_for", _cat)

    def _door(checkpoint, profile, shell_line, output_file, **k):
        door_calls.append({"shell_line": shell_line, "status": checkpoint.status,
                           "approved_by": checkpoint.approved_by, "kind": checkpoint.kind,
                           "exploit_confirmed": checkpoint.exploit_confirmed})
        return {"exit_code": 0, "blocked": None, "missing_tool": None, "stdout_tail": "ok\n"}

    monkeypatch.setattr(sg, "execute_gated_action", _door)


async def _seed(client, monkeypatch, tmp_path, target="10.10.60.7"):
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    from nabu_agent.db.models import Run
    from nabu_agent.db.session import sessionmaker
    from nabu_agent.engine.workspace import workspace_for

    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Attack"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": target})
    workspace_for(pid, target).open_or_create()
    async with sessionmaker()() as db:
        run = Run(project_id=pid, kind="scan", target=target, state="done")
        db.add(run)
        await db.commit()
        run_id = run.id
    return pid, run_id, target


async def _add_cred(client, pid, username="admin", secret="hunter2super", secret_type="password", domain=""):
    await client.post(f"/api/projects/{pid}/credentials",
                      json={"username": username, "secret": secret, "secret_type": secret_type, "domain": domain})
    creds = (await client.get(f"/api/projects/{pid}/credentials")).json()["credentials"]
    return next(c["id"] for c in creds if c["username"] == username)


async def _poll_status(client, run_id, cp_id, want, tries=60):
    for _ in range(tries):
        cps = (await client.get(f"/api/runs/{run_id}/checkpoints")).json()["checkpoints"]
        cp = next((c for c in cps if c["id"] == cp_id), None)
        if cp and cp["status"] == want:
            return cp
        await asyncio.sleep(0.05)
    return None


# --------------------------------------------------------------------------- Phase A gates

async def test_platform_switch_off_blocks_approval(client, monkeypatch, tmp_path):
    door: list = []
    _install(monkeypatch, door)
    from nabu_agent.settings import get_settings
    monkeypatch.setattr(get_settings(), "exploit_enabled", False)
    pid, run_id, target = await _seed(client, monkeypatch, tmp_path)
    await client.patch(f"/api/projects/{pid}/settings", json={"exploit_enabled": True})
    cp_id = (await client.post(f"/api/runs/{run_id}/attack-proposals",
             json={"kind": "exploit", "target": target, "service": "smb", "action_id": "smb-cme-exec"})).json()["checkpoint_id"]
    r = await client.post(f"/api/runs/{run_id}/checkpoints/{cp_id}/approve", json={"exploit_confirmed": True})
    assert r.status_code == 409 and "platform-wide" in r.json()["detail"]
    assert door == []


async def test_bad_action_id_is_not_proposable(client, monkeypatch, tmp_path):
    _install(monkeypatch, [])
    pid, run_id, target = await _seed(client, monkeypatch, tmp_path)
    r = await client.post(f"/api/runs/{run_id}/attack-proposals",
                          json={"kind": "exploit", "target": target, "service": "smb", "action_id": "nope"})
    assert r.status_code == 422 and "not proposable" in r.json()["detail"]


async def test_out_of_scope_target_refused(client, monkeypatch, tmp_path):
    _install(monkeypatch, [])
    pid, run_id, target = await _seed(client, monkeypatch, tmp_path)
    r = await client.post(f"/api/runs/{run_id}/attack-proposals",
                          json={"kind": "exploit", "target": "8.8.8.8", "service": "smb", "action_id": "smb-cme-exec"})
    assert r.status_code == 403


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
                     json={"kind": "exploit", "target": target, "service": "smb", "action_id": "smb-cme-exec"})
    assert r.status_code == 403
    await v.aclose()


# --------------------------------------------------------------------------- Phase C

async def test_credential_injected_at_execute_but_redacted_in_preview(client, monkeypatch, tmp_path):
    door: list = []
    _install(monkeypatch, door, template="crackmapexec smb {target} -u {user} -p {password} -x whoami")
    from nabu_agent.settings import get_settings
    monkeypatch.setattr(get_settings(), "exploit_enabled", True)
    pid, run_id, target = await _seed(client, monkeypatch, tmp_path)
    await client.patch(f"/api/projects/{pid}/settings", json={"exploit_enabled": True})
    cid = await _add_cred(client, pid, username="admin", secret="hunter2super")

    # propose with the credential — the preview is REDACTED (no plaintext), but the command resolves
    r = await client.post(f"/api/runs/{run_id}/attack-proposals",
                          json={"kind": "exploit", "target": target, "service": "smb",
                                "action_id": "smb-cme-exec", "credential_ref": cid})
    assert r.status_code == 200, r.text
    cp_id = r.json()["checkpoint_id"]
    assert "hunter2super" not in r.json()["command"]
    assert "-u admin -p <password:redacted>" in r.json()["command"]

    ok = await client.post(f"/api/runs/{run_id}/checkpoints/{cp_id}/approve", json={"exploit_confirmed": True})
    assert ok.status_code == 200
    assert await _poll_status(client, run_id, cp_id, "executed") is not None

    # the DOOR received the real secret; NO event in the run stream leaked it
    assert door and "hunter2super" in door[0]["shell_line"]
    assert door[0]["status"] == "approved" and door[0]["approved_by"]
    events = (await client.get(f"/api/runs/{run_id}/events")).json()["events"]
    assert "hunter2super" not in str(events)

    # tested_against recorded on the credential
    creds = (await client.get(f"/api/projects/{pid}/credentials")).json()["credentials"]
    assert target in next(c["tested_against"] for c in creds if c["id"] == cid)


async def test_operator_params_fill_remaining_placeholders(client, monkeypatch, tmp_path):
    door: list = []
    _install(monkeypatch, door, template="smbclient -U {user} //{target}/C$ -c '{command}'")
    from nabu_agent.settings import get_settings
    monkeypatch.setattr(get_settings(), "exploit_enabled", True)
    pid, run_id, target = await _seed(client, monkeypatch, tmp_path)
    await client.patch(f"/api/projects/{pid}/settings", json={"exploit_enabled": True})
    cid = await _add_cred(client, pid, username="admin", secret="pw")

    # missing the {command} param → refused, and the message names what's needed
    miss = await client.post(f"/api/runs/{run_id}/attack-proposals",
                             json={"kind": "exploit", "target": target, "service": "smb",
                                   "action_id": "smb-cme-exec", "credential_ref": cid})
    assert miss.status_code == 422 and "command" in miss.json()["detail"]

    # supplying the param resolves it
    r = await client.post(f"/api/runs/{run_id}/attack-proposals",
                          json={"kind": "exploit", "target": target, "service": "smb",
                                "action_id": "smb-cme-exec", "credential_ref": cid,
                                "params": {"command": "dir"}})
    assert r.status_code == 200 and "-c 'dir'" in r.json()["command"]


async def test_spray_requires_credential_then_runs(client, monkeypatch, tmp_path):
    door: list = []
    _install(monkeypatch, door, template="netexec ssh {target} -u {user} -p {password}")
    from nabu_agent.settings import get_settings
    monkeypatch.setattr(get_settings(), "spray_enabled", True)
    pid, run_id, target = await _seed(client, monkeypatch, tmp_path)
    await client.patch(f"/api/projects/{pid}/settings", json={"spray_enabled": True})
    cid = await _add_cred(client, pid, username="svc", secret="Spring2026")

    # a spray needs a credential to even resolve the command
    assert (await client.post(f"/api/runs/{run_id}/attack-proposals",
            json={"kind": "spray", "target": target, "service": "ssh", "action_id": "smb-cme-exec"})).status_code == 422
    cp_id = (await client.post(f"/api/runs/{run_id}/attack-proposals",
             json={"kind": "spray", "target": target, "service": "ssh", "action_id": "smb-cme-exec",
                   "credential_ref": cid})).json()["checkpoint_id"]
    ok = await client.post(f"/api/runs/{run_id}/checkpoints/{cp_id}/approve", json={})
    assert ok.status_code == 200
    assert await _poll_status(client, run_id, cp_id, "executed") is not None
    assert door and "Spring2026" in door[0]["shell_line"]


async def test_per_run_attack_cap(client, monkeypatch, tmp_path):
    _install(monkeypatch, [])
    import nabu_agent.orchestration.limits as lim
    monkeypatch.setattr(lim, "RunLimits", lambda: SimpleNamespace(max_gated_actions_per_run=1, host_job_timeout_s=30))
    pid, run_id, target = await _seed(client, monkeypatch, tmp_path)
    first = await client.post(f"/api/runs/{run_id}/attack-proposals",
                              json={"kind": "exploit", "target": target, "service": "smb", "action_id": "smb-cme-exec"})
    assert first.status_code == 200
    second = await client.post(f"/api/runs/{run_id}/attack-proposals",
                               json={"kind": "exploit", "target": target, "service": "smb", "action_id": "smb-cme-exec"})
    assert second.status_code == 409 and "cap reached" in second.json()["detail"]


async def test_dry_run_shows_command_without_calling_the_door(client, monkeypatch, tmp_path):
    door: list = []
    _install(monkeypatch, door, template="crackmapexec smb {target} -u {user} -p {password} -x whoami")
    from nabu_agent.settings import get_settings
    monkeypatch.setattr(get_settings(), "exploit_enabled", True)
    pid, run_id, target = await _seed(client, monkeypatch, tmp_path)
    await client.patch(f"/api/projects/{pid}/settings", json={"exploit_enabled": True})
    cid = await _add_cred(client, pid, username="admin", secret="hunter2super")
    cp_id = (await client.post(f"/api/runs/{run_id}/attack-proposals",
             json={"kind": "exploit", "target": target, "service": "smb",
                   "action_id": "smb-cme-exec", "credential_ref": cid})).json()["checkpoint_id"]

    ok = await client.post(f"/api/runs/{run_id}/checkpoints/{cp_id}/approve",
                           json={"exploit_confirmed": True, "dry_run": True})
    assert ok.status_code == 200 and ok.json()["dry_run"] is True
    cp = await _poll_status(client, run_id, cp_id, "dry-run")
    assert cp is not None, "dry-run checkpoint never settled"
    assert door == []                                     # the gated door was NEVER called
    events = (await client.get(f"/api/runs/{run_id}/events")).json()["events"]
    assert "would run" in str(events) and "hunter2super" not in str(events)   # shown (redacted), not run
