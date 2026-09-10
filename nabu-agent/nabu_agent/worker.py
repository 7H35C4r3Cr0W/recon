"""Arq worker entrypoint: `arq nabu_agent.worker.WorkerSettings` (docker-compose `worker` service).

The worker runs runs off the api process. Engine calls are blocking, so the driver executes them in
worker threads and fans out per-service agents concurrently. on_startup wires this process's own DB
engine + Redis client (for event publish); the api enqueues jobs via bus.enqueue_run.
"""

from __future__ import annotations

from typing import Any

from arq import cron

from nabu_agent.orchestration import reaper, retention, tasks


async def on_startup(ctx: dict[str, Any]) -> None:
    import redis.asyncio as aioredis

    from nabu_agent import bus
    from nabu_agent.db import session as db_session
    from nabu_agent.obs import logging as obs_logging
    from nabu_agent.settings import get_settings

    s = get_settings()
    obs_logging.configure(s.log_level, s.log_format)
    db_session.configure()                       # this process's async DB engine
    bus.set_client(aioredis.from_url(s.redis_url, decode_responses=True))  # publish channel


async def on_shutdown(ctx: dict[str, Any]) -> None:
    from nabu_agent.db import session as db_session

    await db_session.dispose()


def _redis_settings() -> Any:
    from arq.connections import RedisSettings

    from nabu_agent.settings import get_settings

    return RedisSettings.from_dsn(get_settings().redis_url)


class WorkerSettings:
    functions = [tasks.supervise_run]
    # reap stale/killed runs every 30s so a dead worker's run doesn't stay stuck
    cron_jobs = [
        cron(reaper.reap_job, second={0, 30}, run_at_startup=True),
        cron(retention.retention_job, minute={0}, run_at_startup=True),  # hourly housekeeping
    ]
    on_startup = on_startup
    on_shutdown = on_shutdown
    max_jobs = 16          # concurrent runs; per-run fan-out is bounded separately (RunLimits)
    job_timeout = 3600     # a full run may take a while; per-step watchdog is the engine's 300s
    max_tries = 1          # a run drives its own partial/failed handling; don't blindly re-run tools
    keep_result = 3600
    redis_settings = _redis_settings()  # a RedisSettings instance (DSN parse only, no connection)
