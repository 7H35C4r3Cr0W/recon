"""Add map_regions for group-anchored map annotations (a named box over a set of member nodes).

IDEMPOTENT: on a fresh database the 0001 ``create_all`` baseline already builds ``map_regions`` (the
model is in ``Base.metadata``), so this revision creates the table only if it is missing — mirroring
the 0002/0003 guard pattern.

Revision ID: 0004_map_regions
Revises: 0003_map_notes
Create Date: 2026-09-11
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from nabu_agent.db.models import MapRegion

revision = "0004_map_regions"
down_revision = "0003_map_notes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    table = MapRegion.__table__
    assert isinstance(table, sa.Table)  # narrow FromClause -> Table for .create()
    if not sa.inspect(bind).has_table("map_regions"):
        table.create(bind)


def downgrade() -> None:
    bind = op.get_bind()
    table = MapRegion.__table__
    assert isinstance(table, sa.Table)
    if sa.inspect(bind).has_table("map_regions"):
        table.drop(bind)
