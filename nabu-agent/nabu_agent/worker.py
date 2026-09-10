"""Arq worker entrypoint: ``arq nabu_agent.worker.WorkerSettings``.

Engine calls are synchronous/blocking (``subprocess.Popen`` inside ``shell.run``), so the worker
runs them in threads and keeps its pool separate from the FastAPI process. ``job_timeout`` is a
coarse backstop ABOVE the engine's per-step 300 s watchdog and the per-agent wall clock in
:class:`~nabu_agent.orchestration.limits.RunLimits`.

Two logical pools (supervisor vs agent-work) prevent an awaiting supervisor from starving the
children it is waiting on; here they share one WorkerSettings but the supervisor is written to be
NON-blocking (fan out, return its slot, re-trigger on the last finisher) so a single pool is safe
for the scaffold. Split into two ``arq`` worker deployments in Phase 3 if needed.
"""

from __future__ import annotations

from nabu_agent.orchestration import tasks


class WorkerSettings:
    """Arq worker configuration. ``functions`` are the fan-out task graph."""

    functions = [
        tasks.supervise_run,
        tasks.recon_alive,
        tasks.recon_scan,
        tasks.enum_service,
        tasks.vuln_service,
        tasks.research_service,
        tasks.synthesize_report,
        tasks.execute_approved_action,  # human-gated; enqueued only after approve()
    ]
    max_jobs = 16          # global cap; per-run width bounded by RunLimits
    job_timeout = 1200     # seconds; backstop above the engine's 300s per-step watchdog
    max_tries = 3          # transient infra only; blocked / missing_tool are never retried
    keep_result = 3600
    # redis_settings is wired from Settings.redis_url in on_startup (see Phase 1).


def is_retryable(shell_outcome: str) -> bool:
    """``blocked`` (policy refusal) and ``missing_tool`` (not on PATH) are DATA, not failures — they
    are recorded on the agent_task row and surfaced in the report, never retried. Only transient
    infra (``error`` / ``timeout``) is retryable."""
    return shell_outcome in {"error", "timeout"}
