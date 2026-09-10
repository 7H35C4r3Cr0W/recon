"""Async SQLAlchemy engine + session factory + FastAPI dependency.

The engine is built lazily from ``Settings.database_url`` (asyncpg in prod) so importing this module
never opens a connection — and tests can point it at in-memory SQLite via :func:`configure` before
first use. The pool is disposed in the app lifespan.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from nabu_agent.settings import get_settings

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def configure(url: str | None = None) -> AsyncEngine:
    """(Re)build the engine + sessionmaker. Tests pass a sqlite+aiosqlite URL; prod uses settings."""
    global _engine, _sessionmaker
    dsn = url or get_settings().database_url
    connect_args = {"check_same_thread": False} if dsn.startswith("sqlite") else {}
    _engine = create_async_engine(dsn, pool_pre_ping=not dsn.startswith("sqlite"),
                                  connect_args=connect_args, future=True)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)
    return _engine


def engine() -> AsyncEngine:
    return _engine or configure()


def sessionmaker() -> async_sessionmaker[AsyncSession]:
    if _sessionmaker is None:
        configure()
    assert _sessionmaker is not None
    return _sessionmaker


async def create_all() -> None:
    """Create all tables (dev/test convenience; prod uses Alembic migrations)."""
    from nabu_agent.db.models import Base

    async with engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def dispose() -> None:
    if _engine is not None:
        await _engine.dispose()


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a request-scoped session."""
    async with sessionmaker()() as session:
        yield session
