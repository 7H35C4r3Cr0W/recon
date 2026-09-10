"""One-shot bootstrap: seed the first local admin + default settings when OIDC is off.

Run via ``python -m nabu_agent.bootstrap`` (the compose ``migrate`` step chains it after
``alembic upgrade head``). Idempotent: if any user already exists it does nothing. Wired to the DB
in Phase 1.
"""

from __future__ import annotations


async def seed_admin(email: str, password: str) -> None:
    """Create the first user as a global admin (argon2-hashed password). No-op if users exist."""
    raise NotImplementedError


def main() -> None:  # pragma: no cover - CLI entry
    raise NotImplementedError


if __name__ == "__main__":  # pragma: no cover
    main()
