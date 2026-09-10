"""Seed the first local admin when OIDC is off. Idempotent: no-op if any user exists.
Run via ``python -m nabu_agent.bootstrap`` (compose chains it after ``alembic upgrade head``)."""

from __future__ import annotations

import asyncio
import os

from sqlalchemy import select

from nabu_agent.auth.providers import hash_password
from nabu_agent.db.models import User
from nabu_agent.db.session import create_all, dispose, sessionmaker


async def seed_admin(email: str, password: str, display_name: str = "admin") -> str | None:
    """Create the first user as a global admin. Returns the user id, or None if users already exist."""
    async with sessionmaker()() as db:
        existing = (await db.execute(select(User).limit(1))).scalar_one_or_none()
        if existing is not None:
            return None
        user = User(email=email, display_name=display_name, role="admin",
                    auth_source="local", password_hash=hash_password(password))
        db.add(user)
        await db.commit()
        return user.id


async def _main() -> None:
    await create_all()  # dev convenience; prod relies on alembic having run first
    email = os.environ.get("NABU_ADMIN_EMAIL", "admin@nabu.local")
    password = os.environ.get("NABU_ADMIN_PASSWORD", "changeme")
    uid = await seed_admin(email, password)
    print(f"seeded admin {email}" if uid else "users already present — no seed")
    await dispose()


def main() -> None:  # pragma: no cover - CLI
    asyncio.run(_main())


if __name__ == "__main__":  # pragma: no cover
    main()
