"""Run dispatch: with use_arq the API enqueues onto the Arq worker (doesn't run in-process); the
supervise_run job delegates to the run driver."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_start_enqueues_when_use_arq(monkeypatch):
    import nabu_agent.services.runs as runs
    from nabu_agent.settings import get_settings

    monkeypatch.setenv("NABU_USE_ARQ", "true")
    get_settings.cache_clear()
    enqueued, launched = [], []
    monkeypatch.setattr("nabu_agent.bus.enqueue_run",
                        lambda *a, **k: enqueued.append(a) or _acoro())
    monkeypatch.setattr(runs, "launch", lambda *a, **k: launched.append(a))
    await runs.start("r1", "10.10.10.5", "scan", project_id="p1")
    assert enqueued and not launched
    get_settings.cache_clear()


async def _acoro():
    return None


async def test_start_runs_in_process_when_disabled(monkeypatch):
    import nabu_agent.services.runs as runs
    from nabu_agent.settings import get_settings

    monkeypatch.setenv("NABU_USE_ARQ", "false")
    get_settings.cache_clear()
    launched = []
    monkeypatch.setattr(runs, "launch", lambda *a, **k: launched.append(a))
    await runs.start("r1", "10.10.10.5", "demo", project_id="p1")
    assert launched
    get_settings.cache_clear()


async def test_supervise_run_delegates_to_driver(monkeypatch):
    import nabu_agent.services.runs as runs
    from nabu_agent.orchestration import tasks

    calls = []
    async def fake_execute(run_id, target, kind, *, project_id=None):
        calls.append((run_id, target, kind, project_id))
    monkeypatch.setattr(runs, "execute_run", fake_execute)
    out = await tasks.supervise_run({}, "r9", "10.10.10.5", "scan", "p9")
    assert calls == [("r9", "10.10.10.5", "scan", "p9")] and out.startswith("r9")
