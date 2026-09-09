"""WebSocket hub: cookie-auth handshake, project-read RBAC, replay ``run_events`` by ``seq`` then
tail the Redis ``run:{id}`` channel. Server emits a ~20s heartbeat decoupled from scan output and
coalesces ``task.updated``/``log.line`` into ~250ms batches. Consumes the canonical
:class:`nabu_agent.events.schema.Event`. Bodies wired in Phase 2.
"""

from __future__ import annotations

from typing import Any


class RunHub:
    """One instance per connected client watching one run."""

    def __init__(self, run_id: str, user_id: str) -> None:
        self.run_id = run_id
        self.user_id = user_id

    async def replay_then_tail(self, websocket: Any) -> None:
        """Send persisted run_events (seq-ordered) so a mid-run reconnect reconciles to Postgres,
        then subscribe to the Redis channel and forward live events. Coalesce + heartbeat."""
        raise NotImplementedError
