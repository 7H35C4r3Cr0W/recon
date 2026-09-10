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

DEFAULT_GLOBAL_RUN_CEILING = 8
_PROJECT_MUTEX_PREFIX = "nabu:run:project-mutex:"


def project_mutex_key(profile_dir: str) -> str:
    """Redis key for the per-project single-writer mutex (held for the run lifetime)."""
    return _PROJECT_MUTEX_PREFIX + profile_dir


async def acquire_run_slot(project_id: str, profile_dir: str) -> bool:
    """Try to admit a new run: take the per-project mutex and check the global ceiling.

    Returns True if admitted (caller enqueues ``supervise_run``), False if a run is already active
    for the project or the global ceiling is hit. Implemented in Phase 1 against
    :mod:`nabu_agent.bus`.
    """
    raise NotImplementedError


async def release_run_slot(project_id: str, profile_dir: str) -> None:
    """Release the per-project mutex when the run reaches a terminal state."""
    raise NotImplementedError
