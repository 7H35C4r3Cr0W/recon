"""Arq task functions — the run's execution home on the worker pool.

`supervise_run` is the Arq job the API enqueues (via bus.enqueue_run). It delegates to the run
DRIVER (services.runs.execute_run), which performs the state machine, the per-service fan-out
(concurrent enum agents), and event streaming. Keeping the driver in one place means demo, real, and
LLM-agent runs behave identically whether executed in-process (dev/tests) or on the worker
(production) — the only difference is WHERE the coroutine runs.

The blocking oscprecon engine calls inside the driver run in worker threads (asyncio.to_thread); the
fan-out runs those threads concurrently under a semaphore, so several service agents are 'active'
(green) on the live map at once, then the run joins and synthesizes the report.
"""

from __future__ import annotations

from typing import Any


async def supervise_run(ctx: dict[str, Any], run_id: str, target: str, kind: str,
                        project_id: str) -> str:
    """Arq entrypoint for one run — the lightweight SUPERVISOR. Delegates to execute_run, which does
    admission + alive-sweep + the approval gate, then (in production) fans out one recon_host_job per
    host onto the pool and awaits their results, owning the single terminal DONE. Returns a summary."""
    from nabu_agent.services.runs import execute_run

    await execute_run(run_id, target, kind, project_id=project_id)
    # execute_run persists the terminal state; return a small summary for arq's result store.
    return f"{run_id}:{kind}"


async def recon_host_job(ctx: dict[str, Any], run_id: str, host: str, kind: str,
                         project_id: str, service_budget: int) -> str:
    """Per-host WORKER job: recon ONE host of a run on the pool (two-pool fan-out). The supervisor
    enqueues one of these per live host and awaits its result. Returns the host's terminal string."""
    from nabu_agent.services.runs import run_host_in_worker

    return await run_host_in_worker(run_id, host, kind, project_id, int(service_budget))


async def execute_approved_action(ctx: dict[str, Any], checkpoint_id: str) -> str:
    """Arq entrypoint for a human-approved spray/exploit checkpoint. Delegates to the driver, which
    re-verifies the approval + gates, re-derives the command from the catalog, and runs it through
    the one gated door. Returns a short ``<cp_id>:<outcome>`` summary for arq's result store."""
    from nabu_agent.services.runs import execute_approved_action as _run

    return await _run(checkpoint_id)
