"""Shared fixtures. Integration tests get a temp-file async SQLite DB (shared across the executor's
own connections — in-memory sqlite is per-connection, which would hide the background task's writes),
a fakeredis client wired into the bus, a seeded admin, and an httpx client bound to the ASGI app.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


@pytest.fixture
async def app_ctx():
    """Configure DB (temp-file sqlite) + fakeredis + seeded admin, yield (app, admin creds)."""
    import os

    os.environ["NABU_ENV"] = "development"  # so the session cookie isn't Secure-only over http
    os.environ["NABU_USE_ARQ"] = "false"    # always run in-process in tests, even if a stray .env sets it
    import fakeredis.aioredis
    from nabu_agent import bus
    from nabu_agent.bootstrap import seed_admin
    from nabu_agent.db import session as db_session
    from nabu_agent.settings import get_settings

    get_settings.cache_clear()

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db_session.configure(f"sqlite+aiosqlite:///{tmp.name}")
    await db_session.create_all()
    bus.set_client(fakeredis.aioredis.FakeRedis(decode_responses=True))
    await seed_admin("admin@nabu.local", "changeme")

    from nabu_agent.main import create_app
    app = create_app()
    yield app, {"email": "admin@nabu.local", "password": "changeme"}

    await db_session.dispose()
    bus.set_client(None)
    pathlib.Path(tmp.name).unlink(missing_ok=True)


@pytest.fixture
async def client(app_ctx):
    import httpx
    app, _creds = app_ctx
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
