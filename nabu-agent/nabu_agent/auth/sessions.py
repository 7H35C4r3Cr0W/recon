"""Redis-backed opaque sessions in an httpOnly, SameSite cookie, plus a per-user session index so
OIDC back-channel logout can revoke ALL of a user's sessions. The WebSocket handshake reuses the same
cookie (no token-in-URL). TTL from ``Settings.session_ttl_min``."""

from __future__ import annotations

import secrets

from nabu_agent import bus
from nabu_agent.settings import get_settings

COOKIE_NAME = "nabu_session"
_PREFIX = "nabu:session:"
_USER_PREFIX = "nabu:user-sessions:"


def _key(sid: str) -> str:
    return _PREFIX + sid


def _user_key(user_id: str) -> str:
    return _USER_PREFIX + user_id


async def create_session(user_id: str) -> str:
    sid = secrets.token_urlsafe(32)
    ttl = get_settings().session_ttl_min * 60
    r = bus.get_redis()
    await r.set(_key(sid), user_id, ex=ttl)
    await r.sadd(_user_key(user_id), sid)          # index for revoke-all (back-channel logout)
    await r.expire(_user_key(user_id), ttl)
    return sid


async def resolve_session(sid: str | None) -> str | None:
    if not sid:
        return None
    val = await bus.get_redis().get(_key(sid))
    if val is None:
        return None
    return val if isinstance(val, str) else val.decode()


async def destroy_session(sid: str | None) -> None:
    if not sid:
        return
    r = bus.get_redis()
    uid = await resolve_session(sid)
    await r.delete(_key(sid))
    if uid:
        await r.srem(_user_key(uid), sid)


async def destroy_user_sessions(user_id: str) -> int:
    """Revoke every session for a user (OIDC back-channel logout / admin kill). Returns the count."""
    r = bus.get_redis()
    members = await r.smembers(_user_key(user_id))
    sids = [m if isinstance(m, str) else m.decode() for m in (members or [])]
    for sid in sids:
        await r.delete(_key(sid))
    await r.delete(_user_key(user_id))
    return len(sids)
