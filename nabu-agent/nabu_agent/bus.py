"""The single Redis interaction surface: Arq enqueue, run cancel-flag, and pub/sub for live events.

Keeping all Redis access here (rather than scattered ``redis`` calls) makes the event contract and
key namespace auditable in one place. Keys:

    nabu:run:{run_id}:events      pub/sub channel — engine on_line lines + state deltas → WebSocket
    nabu:run:{run_id}:cancel      cancel flag — set by /runs/{id}/cancel, polled by tasks
    nabu:run:{run_id}:fanin       DECR counter — the re-trigger-on-last-finisher barrier
    nabu:run:project-mutex:{dir}  per-project single-writer mutex (see admission.py)

Bodies are wired to redis-py asyncio in Phase 1; signatures are the contract.
"""

from __future__ import annotations

from typing import Any


def events_channel(run_id: str) -> str:
    return f"nabu:run:{run_id}:events"


def cancel_key(run_id: str) -> str:
    return f"nabu:run:{run_id}:cancel"


def fanin_key(run_id: str) -> str:
    return f"nabu:run:{run_id}:fanin"


async def publish_event(run_id: str, event: dict[str, Any]) -> None:
    """Publish one canonical Event (see events/schema.py) to the run channel."""
    raise NotImplementedError


async def request_cancel(run_id: str) -> None:
    """Set the run's cancel flag; tasks derive a threading.Event from it for shell.run(cancel=)."""
    raise NotImplementedError


async def is_cancelled(run_id: str) -> bool:
    raise NotImplementedError
