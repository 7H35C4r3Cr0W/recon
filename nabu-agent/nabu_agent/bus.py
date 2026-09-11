"""The single Redis interaction surface: live event pub/sub, per-run cancel flag, and the per-run
monotonic seq counter that drives WebSocket replay-by-seq. Keeping all Redis access here makes the
key namespace auditable in one place.

Keys:
    nabu:run:{id}:events   pub/sub channel — node-state + log events → WebSocket
    nabu:run:{id}:cancel   cancel flag — set by /runs/{id}/cancel, polled by the executor
    nabu:run:{id}:seq      INCR counter — the per-run monotonic event seq
"""

from __future__ import annotations

import contextlib
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


# --- login brute-force throttle (per ip+email, sliding-ish window via TTL) ---
LOGIN_MAX_FAILURES = 8          # failures allowed within the window before a temporary block
LOGIN_WINDOW_S = 900            # 15 min


def _login_key(ip: str, email: str) -> str:
    return f"nabu:login-fail:{ip}|{email.lower()}"


async def login_failure_count(ip: str, email: str) -> int:
    return int(await get_redis().get(_login_key(ip, email)) or 0)


async def register_login_failure(ip: str, email: str) -> int:
    """INCR the failure counter for (ip, email); set the window TTL on first failure. Returns count."""
    r = get_redis()
    key = _login_key(ip, email)
    n = int(await r.incr(key))
    if n == 1:
        await r.expire(key, LOGIN_WINDOW_S)
    return n


async def clear_login_failures(ip: str, email: str) -> None:
    await get_redis().delete(_login_key(ip, email))


async def attack_cooldown_ttl(project_id: str) -> int:
    """Seconds left on a project's gated-execution cooldown (0 = clear). Best-effort; a Redis blip
    reads as 'clear' so the gate never wedges on infra."""
    try:
        ttl = int(await get_redis().ttl(f"attack:cooldown:{project_id}"))
    except Exception:
        return 0
    return ttl if ttl > 0 else 0


async def set_attack_cooldown(project_id: str, seconds: int) -> None:
    """Start the per-project cooldown after a gated action fires. Best-effort."""
    if seconds > 0:
        with contextlib.suppress(Exception):
            await get_redis().set(f"attack:cooldown:{project_id}", "1", ex=seconds)


async def request_cancel(run_id: str) -> None:
    await get_redis().set(cancel_key(run_id), "1")


async def is_cancelled(run_id: str) -> bool:
    return bool(await get_redis().get(cancel_key(run_id)))


# --- Arq queue (production run execution on the worker pool) ---
_arq_pool: Any = None


async def get_arq_pool() -> Any:
    """Cached Arq redis pool for enqueuing run jobs onto the worker."""
    global _arq_pool
    if _arq_pool is None:
        from arq import create_pool
        from arq.connections import RedisSettings
        _arq_pool = await create_pool(RedisSettings.from_dsn(get_settings().redis_url))
    return _arq_pool


def set_arq_pool(pool: Any) -> None:
    global _arq_pool
    _arq_pool = pool


async def enqueue_run(run_id: str, target: str, kind: str, project_id: str) -> None:
    """Enqueue the supervisor job for a run onto the Arq worker pool."""
    pool = await get_arq_pool()
    await pool.enqueue_job("supervise_run", run_id, target, kind, project_id, _job_id=f"run:{run_id}")


async def close_arq_pool() -> None:
    """Close the cached Arq pool on shutdown (avoids a leaked connection)."""
    global _arq_pool
    if _arq_pool is not None:
        with contextlib.suppress(Exception):
            await _arq_pool.aclose()
        _arq_pool = None
