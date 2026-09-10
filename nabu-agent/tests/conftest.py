"""Shared fixtures. Policy-invariant AST tests need nothing; integration tests get an in-memory
async SQLite DB (no Postgres), a fakeredis client, and a FastAPI app with the engine adapter mocked.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


@pytest.fixture
async def db():
    """A fresh in-memory SQLite DB per test (tables created), yielding a session factory."""
    from nabu_agent.db import session as db_session
    db_session.configure("sqlite+aiosqlite:///:memory:")
    await db_session.create_all()
    yield db_session
    await db_session.dispose()


@pytest.fixture
def fake_redis():
    """A fakeredis async client (no server needed)."""
    import fakeredis.aioredis
    return fakeredis.aioredis.FakeRedis()
