"""Two-pool distributed supervisor (NABU_USE_ARQ). The supervisor enqueues one recon_host_job per
live host onto the worker pool and awaits their results; each host writes its own per-host Profile.
A fake Arq pool runs the enqueued task functions inline so the choreography is exercised
deterministically. Also covers admission: a project with an active run refuses a second."""
from __future__ import annotations

import asyncio

import pytest
from nabu_agent import bus

from tests._mocks import install_recon_mocks

pytestmark = pytest.mark.asyncio


class _FakeJob:
    def __init__(self, result):
        self._result = result

    async def result(self, timeout=None):
        return self._result


class _FakePool:
    """Runs each enqueued Arq task function inline against the in-process app, so a supervisor's
    fan-out to recon_host_job (and the api's supervise_run enqueue) executes end to end in tests."""
    def __init__(self):
        self.enqueued: list[tuple[str, tuple]] = []

    async def enqueue_job(self, fn: str, *args, _job_id=None, **kwargs):
        self.enqueued.append((fn, args))
        from nabu_agent.orchestration import tasks
        return _FakeJob(await getattr(tasks, fn)({}, *args))


def _install(monkeypatch, tmp_path, live_hosts):
    install_recon_mocks(monkeypatch, tmp_path, live_hosts=live_hosts)

def _use_arq(monkeypatch, on=True):
    from nabu_agent.settings import get_settings
    monkeypatch.setenv("NABU_USE_ARQ", "true" if on else "false")
    get_settings.cache_clear()


async def test_distributed_cidr_fans_out_via_host_jobs(client, monkeypatch, tmp_path):
    _use_arq(monkeypatch)
    pool = _FakePool()
    bus.set_arq_pool(pool)
    _install(monkeypatch, tmp_path, ["10.10.10.5", "10.10.10.6", "10.10.10.7"])   # < threshold, no gate
    try:
        await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
        pid = (await client.post("/api/projects", json={"display_name": "Dist"})).json()["id"]
        await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.0/29"})
        run_id = (await client.post(f"/api/projects/{pid}/runs",
                                    json={"target": "10.10.10.0/29", "kind": "scan"})).json()["run_id"]

        node_ids, types = set(), set()
        for _ in range(200):
            await asyncio.sleep(0.05)
            for e in (await client.get(f"/api/runs/{run_id}/events")).json()["events"]:
                types.add(e["type"])
                if e["data"].get("node_id"):
                    node_ids.add(e["data"]["node_id"])
            if "done" in types:
                break
        assert "done" in types, f"distributed run did not finish; types={types}"
    finally:
        bus.set_arq_pool(None)
        _use_arq(monkeypatch, on=False)

    # the supervisor enqueued one recon_host_job PER host onto the (fake) pool
    fns = [fn for fn, _ in pool.enqueued]
    assert fns.count("supervise_run") == 1
    assert fns.count("recon_host_job") == 3
    # and every host was actually recon'd (host-scoped nodes emitted by the per-host jobs)
    for h in ("10.10.10.5", "10.10.10.6", "10.10.10.7"):
        assert f"host-{h}" in node_ids
        assert f"agent-enum-{h}-445" in node_ids
    assert (await client.get(f"/api/runs/{run_id}")).json()["state"] in {"done", "partial"}


async def test_admission_refuses_second_run_on_a_busy_project(client, monkeypatch, tmp_path):
    monkeypatch.setenv("NABU_AGENT_WORKSPACE_ROOT", str(tmp_path))
    from nabu_agent.engine.workspace import project_root
    from nabu_agent.orchestration import admission

    await client.post("/api/auth/login", json={"email": "admin@nabu.local", "password": "changeme"})
    pid = (await client.post("/api/projects", json={"display_name": "Busy"})).json()["id"]
    await client.post(f"/api/projects/{pid}/scope", json={"target": "10.10.10.5"})

    # hold the project's run slot as if a run were already active
    assert await admission.acquire_run_slot(pid, str(project_root(pid))) is True

    run_id = (await client.post(f"/api/projects/{pid}/runs",
                                json={"target": "10.10.10.5", "kind": "demo"})).json()["run_id"]
    state, saw_error = None, False
    for _ in range(80):
        await asyncio.sleep(0.05)
        evs = (await client.get(f"/api/runs/{run_id}/events")).json()["events"]
        saw_error = saw_error or any(e["type"] == "error" for e in evs)
        state = (await client.get(f"/api/runs/{run_id}")).json()["state"]
        if state in {"done", "failed", "cancelled", "partial"}:
            break
    assert state == "failed", f"a run on a busy project should be refused, got {state}"
    assert saw_error
    await admission.release_run_slot(pid, str(project_root(pid)))
