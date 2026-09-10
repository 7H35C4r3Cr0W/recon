"""The single Redis interaction surface: live event pub/sub, per-run cancel flag, and the per-run
monotonic seq counter that drives WebSocket replay-by-seq. Keeping all Redis access here makes the
key namespace auditable in one place.

Keys:
    nabu:run:{id}:events   pub/sub channel — node-state + log events → WebSocket
    nabu:run:{id}:cancel   cancel flag — set by /runs/{id}/cancel, polled by the executor
    nabu:run:{id}:seq      INCR counter — the per-run monotonic event seq
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

from nabu_agent.settings import get_settings

_client: Any = None


def set_client(client: Any) -> None:
    """Inject a client (tests pass fakeredis; app lifespan sets the real one)."""
    global _client
    _client = client


def get_redis() -> Any:
    global _client
    if _client is None:
        import redis.asyncio as aioredis
        _client = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    return _client


def events_channel(run_id: str) -> str:
    return f"nabu:run:{run_id}:events"


def cancel_key(run_id: str) -> str:
    return f"nabu:run:{run_id}:cancel"


def seq_key(run_id: str) -> str:
    return f"nabu:run:{run_id}:seq"


async def next_seq(run_id: str) -> int:
    return int(await get_redis().incr(seq_key(run_id)))


async def publish_event(run_id: str, event: dict[str, Any]) -> None:
    await get_redis().publish(events_channel(run_id), json.dumps(event))


async def open_subscription(run_id: str) -> Any:
    """Create a pubsub and eagerly complete the Redis SUBSCRIBE, so no event published after this
    returns can be missed. Pair with :func:`listen` (and close the returned pubsub when done)."""
    pubsub = get_redis().pubsub()
    await pubsub.subscribe(events_channel(run_id))
    return pubsub


async def listen(pubsub: Any) -> AsyncIterator[dict[str, Any]]:
    """Yield JSON-decoded events from an already-subscribed pubsub."""
    async for message in pubsub.listen():
        if message.get("type") == "message":
            data = message["data"]
            yield json.loads(data if isinstance(data, str) else data.decode())


async def subscribe(run_id: str) -> AsyncIterator[dict[str, Any]]:
    """Convenience: open a subscription and yield live events (lazy SUBSCRIBE on first iteration)."""
    pubsub = await open_subscription(run_id)
    try:
        async for ev in listen(pubsub):
            yield ev
    finally:
        await pubsub.unsubscribe(events_channel(run_id))
        await pubsub.aclose()


async def request_cancel(run_id: str) -> None:
    await get_redis().set(cancel_key(run_id), "1")


async def is_cancelled(run_id: str) -> bool:
    return bool(await get_redis().get(cancel_key(run_id)))
