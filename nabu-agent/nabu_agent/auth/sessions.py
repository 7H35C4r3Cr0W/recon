"""Redis-backed opaque sessions in an httpOnly, SameSite=strict cookie. The WebSocket handshake
reuses the same cookie (no token-in-URL). TTL from ``Settings.session_ttl_min``."""

from __future__ import annotations

import secrets

from nabu_agent import bus
from nabu_agent.settings import get_settings

COOKIE_NAME = "nabu_session"
_PREFIX = "nabu:session:"


def _key(sid: str) -> str:
    return _PREFIX + sid


async def create_session(user_id: str) -> str:
    sid = secrets.token_urlsafe(32)
    ttl = get_settings().session_ttl_min * 60
    await bus.get_redis().set(_key(sid), user_id, ex=ttl)
    return sid


async def resolve_session(sid: str | None) -> str | None:
    if not sid:
        return None
    val = await bus.get_redis().get(_key(sid))
    if val is None:
        return None
    return val if isinstance(val, str) else val.decode()


async def destroy_session(sid: str | None) -> None:
    if sid:
        await bus.get_redis().delete(_key(sid))
