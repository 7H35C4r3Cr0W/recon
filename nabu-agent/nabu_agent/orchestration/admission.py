"""Run admission control — the caps that stop concurrent runs from racing one Profile folder.

Two guarantees:

1. **One active run per project.** The DB carries a partial-unique index on
   ``runs(project_id) WHERE state NOT IN terminal``; this module additionally takes a Redis mutex
   keyed on the project's ``profile_dir`` for the whole run lifetime. Together they make the
   supervisor the single writer of ``profile.json`` (the engine only guards it with an advisory
   ``.lock``, so cross-process serialisation is our responsibility) and stop a retried job from
   starting a second supervisor.
2. **A global concurrent-run ceiling** so a burst of launches cannot exhaust the worker pool.

The functions below are thin, side-effect-light wrappers; the concrete Redis calls live in
:mod:`nabu_agent.bus`. Bodies are filled in Phase 1.
"""

from __future__ import annotations

from nabu_agent import bus

DEFAULT_GLOBAL_RUN_CEILING = 8
RUN_SLOT_TTL_S = 2 * 3600  # safety expiry so a crashed supervisor can't wedge a project forever
_PROJECT_MUTEX_PREFIX = "nabu:run:project-mutex:"
_GLOBAL_ACTIVE_KEY = "nabu:run:global-active"


def project_mutex_key(profile_dir: str) -> str:
    """Redis key for the per-project single-writer mutex (held for the run lifetime)."""
    return _PROJECT_MUTEX_PREFIX + profile_dir


async def acquire_run_slot(project_id: str, profile_dir: str,
                           *, ceiling: int = DEFAULT_GLOBAL_RUN_CEILING) -> bool:
    """Admit a new run: take the per-project mutex (SET NX, TTL) and check the global ceiling.

    Returns True if admitted (the supervisor may fan out), False if a run is already active for the
    project or the global concurrent-run ceiling is hit. Idempotent-safe: the mutex carries a TTL so
    a crashed supervisor cannot wedge a project past ``RUN_SLOT_TTL_S``.
    """
    r = bus.get_redis()
    key = project_mutex_key(profile_dir)
    got = await r.set(key, project_id, nx=True, ex=RUN_SLOT_TTL_S)
    if not got:
        return False  # another run already holds this project's Profile
    n = int(await r.incr(_GLOBAL_ACTIVE_KEY))
    if n > ceiling:
        # over the global ceiling — roll back this admission and refuse
        await r.decr(_GLOBAL_ACTIVE_KEY)
        await r.delete(key)
        return False
    return True


async def release_run_slot(project_id: str, profile_dir: str) -> None:
    """Release the per-project mutex + decrement the global counter when the run is terminal."""
    r = bus.get_redis()
    await r.delete(project_mutex_key(profile_dir))
    n = int(await r.decr(_GLOBAL_ACTIVE_KEY))
    if n < 0:  # never let a double-release drive the counter negative
        await r.set(_GLOBAL_ACTIVE_KEY, 0)
