"""Redis-backed opaque sessions in an httpOnly, SameSite=strict, Secure cookie.

The WebSocket handshake reuses the SAME cookie (no token-in-URL). Session TTL from
``Settings.session_ttl_min``. Bodies wired in Phase 2.
"""

from __future__ import annotations

COOKIE_NAME = "nabu_session"


async def create_session(user_id: str) -> str:
    """Mint an opaque session id, store {user_id, expires} in Redis, return the cookie value."""
    raise NotImplementedError


async def resolve_session(session_id: str) -> str | None:
    """Return the user id for a live session, or None if missing/expired."""
    raise NotImplementedError


async def destroy_session(session_id: str) -> None:
    raise NotImplementedError
