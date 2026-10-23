"""Add key_check_value commitment column to cas_key_versions.

Revision ID: 003_add_key_check_value
Revises: 002_protected_scopes
Create Date: 2026-10-22
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "003_add_key_check_value"
down_revision: str | None = "002_protected_scopes"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "cas_key_versions",
        sa.Column("key_check_value", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("cas_key_versions", "key_check_value")
