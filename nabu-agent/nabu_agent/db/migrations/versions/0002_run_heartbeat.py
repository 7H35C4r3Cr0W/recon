"""Add runs.heartbeat_at for the stale-run reaper.

IDEMPOTENT: the 0001 baseline uses ``Base.metadata.create_all`` (it reflects the CURRENT model, which
already includes ``heartbeat_at``), so on a FRESH database this column exists before 0002 runs — a
blind ``add_column`` would fail with "duplicate column". We therefore add it only if missing. Any
incremental migration on a create_all baseline must guard column adds the same way.

Revision ID: 0002_run_heartbeat
Revises: 0001_init
Create Date: 2026-09-09
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_run_heartbeat"
down_revision = "0001_init"
branch_labels = None
depends_on = None


def _has_column(name: str) -> bool:
    cols = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("runs")}
    return name in cols


def upgrade() -> None:
    if not _has_column("heartbeat_at"):
        op.add_column("runs", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    if _has_column("heartbeat_at"):
        op.drop_column("runs", "heartbeat_at")
