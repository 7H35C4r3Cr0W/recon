"""Add map_notes for per-node operator annotations on the recon map.

IDEMPOTENT: on a fresh database the 0001 ``create_all`` baseline already builds ``map_notes`` (the
model is in ``Base.metadata``), so this revision creates the table only if it is missing — mirroring
0002's guard pattern for incremental migrations on a create_all baseline.

Revision ID: 0003_map_notes
Revises: 0002_run_heartbeat
Create Date: 2026-09-11
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from nabu_agent.db.models import MapNote

revision = "0003_map_notes"
down_revision = "0002_run_heartbeat"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    table = MapNote.__table__
    assert isinstance(table, sa.Table)  # narrow FromClause -> Table for .create()
    if not sa.inspect(bind).has_table("map_notes"):
        table.create(bind)


def downgrade() -> None:
    bind = op.get_bind()
    table = MapNote.__table__
    assert isinstance(table, sa.Table)
    if sa.inspect(bind).has_table("map_notes"):
        table.drop(bind)
