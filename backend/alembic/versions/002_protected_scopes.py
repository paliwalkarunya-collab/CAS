"""Add protected policy-scope storage for new CAS-SE envelopes."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "002_protected_scopes"
down_revision: str | None = "001_initial_cas_overlay"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("cas_data_envelopes", sa.Column("dataset_scope_token", sa.String(96)))
    op.create_index(
        "ix_cas_data_envelopes_dataset_scope_token", "cas_data_envelopes", ["dataset_scope_token"]
    )


def downgrade() -> None:
    op.drop_index("ix_cas_data_envelopes_dataset_scope_token", table_name="cas_data_envelopes")
    op.drop_column("cas_data_envelopes", "dataset_scope_token")
