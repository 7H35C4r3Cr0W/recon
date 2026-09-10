"""Initial schema.

Creates every platform + orchestration table from ``nabu_agent.db.models`` and adds the
partial-unique index that enforces ONE active run per project (Postgres). Using metadata
create_all here is deliberate for the first revision — subsequent revisions use autogenerate diffs.

Revision ID: 0001_init
Revises:
Create Date: 2026-09-09
"""

from __future__ import annotations

from alembic import op
from nabu_agent.db.models import Base

revision = "0001_init"
down_revision = None
branch_labels = None
depends_on = None

# Terminal run states — a project may have at most one run NOT in this set.
_TERMINAL = ("done", "partial", "failed", "cancelled")


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind)
    if bind.dialect.name == "postgresql":
        states = ", ".join(f"'{s}'" for s in _TERMINAL)
        op.execute(
            f"CREATE UNIQUE INDEX IF NOT EXISTS uq_one_active_run_per_project "
            f"ON runs (project_id) WHERE state NOT IN ({states})"
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP INDEX IF EXISTS uq_one_active_run_per_project")
    Base.metadata.drop_all(bind)
