"""Add runs.heartbeat_at for the stale-run reaper.

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


def upgrade() -> None:
    op.add_column("runs", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("runs", "heartbeat_at")
