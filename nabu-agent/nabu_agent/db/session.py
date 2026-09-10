"""Async SQLAlchemy engine + session factory + FastAPI dependency.

The URL comes from ``Settings.database_url`` (asyncpg driver). The pool is created in the app
lifespan (``main.py``) and disposed on shutdown.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from nabu_agent.settings import get_settings

_settings = get_settings()
engine = create_async_engine(_settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a request-scoped session."""
    async with SessionLocal() as session:
        yield session
