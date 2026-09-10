"""Alembic environment. Uses a SYNC engine derived from Settings.database_url (strips the +asyncpg
driver) so migrations run without an event loop; the app itself uses the async engine.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from nabu_agent.db.models import Base
from nabu_agent.settings import get_settings
from sqlalchemy import create_engine, pool

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _sync_url() -> str:
    """Derive a SYNC driver URL for migrations from the async app URL.

    A bare ``postgresql://`` would resolve to psycopg2 (not a dependency), so map the async asyncpg
    URL to psycopg3 (``postgresql+psycopg``), which IS installed. SQLite maps aiosqlite → the stdlib
    sync driver.
    """
    url = get_settings().database_url
    if url.startswith("sqlite"):
        return url.replace("+aiosqlite", "")
    return url.replace("+asyncpg", "+psycopg").replace("postgresql+psycopg+psycopg", "postgresql+psycopg")


def run_migrations_offline() -> None:
    context.configure(url=_sync_url(), target_metadata=target_metadata, literal_binds=True,
                       dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_sync_url(), poolclass=pool.NullPool, future=True)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
