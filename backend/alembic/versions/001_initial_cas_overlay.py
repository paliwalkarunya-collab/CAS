"""Initial CAS-SE Schema Overlay Migration.

Revision ID: 001_initial_cas_overlay
Revises:
Create Date: 2026-10-13 12:00:00.000000

Adds the 11 CAS-SE tables to the organization's existing database without modifying
or conflicting with existing tables. All tables use the `cas_` namespace prefix.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "001_initial_cas_overlay"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    # 1. cas_users
    op.create_table(
        "cas_users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("username", sa.String(length=128), nullable=False, unique=True),
        sa.Column("email", sa.String(length=256), nullable=True, unique=True),
        sa.Column("hashed_password", sa.String(length=512), nullable=False),
        sa.Column(
            "role",
            sa.Enum("admin", "uploader", "trainer", "researcher", "auditor", name="cas_user_role"),
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. cas_refresh_tokens
    op.create_table(
        "cas_refresh_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cas_users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(length=256), nullable=False, unique=True),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )

    # 3. cas_policies
    op.create_table(
        "cas_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=256), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("rego_policy", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cas_users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 4. cas_policy_versions
    op.create_table(
        "cas_policy_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "policy_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cas_policies.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("rego_snapshot", sa.Text(), nullable=False),
        sa.Column("snapshot_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("policy_id", "version_number", name="uq_cas_policy_version"),
    )

    # 5. cas_data_envelopes
    op.create_table(
        "cas_data_envelopes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("object_uri", sa.String(length=1024), nullable=False, unique=True),
        sa.Column("nonce_hex", sa.String(length=24), nullable=False),
        sa.Column("wrapped_dek", sa.Text(), nullable=False),
        sa.Column("kek_version", sa.Integer(), nullable=False),
        sa.Column("ciphertext_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "sensitivity_label", sa.String(length=64), nullable=False, server_default="restricted"
        ),
        sa.Column("dataset_id", sa.String(length=256), nullable=True),
        sa.Column("filename_hash", sa.String(length=64), nullable=True),
        sa.Column("content_type", sa.String(length=128), nullable=True),
        sa.Column("file_size_bytes", sa.Integer(), nullable=True),
        sa.Column("encryption_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "uploaded_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cas_users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "policy_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cas_policies.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 6. cas_protected_indexes
    op.create_table(
        "cas_protected_indexes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "envelope_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cas_data_envelopes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("field_name", sa.String(length=128), nullable=False),
        sa.Column("hmac_token", sa.LargeBinary(length=32), nullable=False),
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "field_name",
            "token_version",
            "hmac_token",
            "envelope_id",
            name="uq_cas_protected_index",
        ),
    )
    op.create_index(
        "ix_cas_protected_index_field_token", "cas_protected_indexes", ["field_name", "hmac_token"]
    )

    # 7. cas_ml_jobs
    op.create_table(
        "cas_ml_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "requester_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cas_users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("purpose", sa.String(length=512), nullable=False),
        sa.Column("dataset_scope", sa.Text(), nullable=False),
        sa.Column(
            "requested_view",
            sa.Enum(
                "metadata_only", "masked_image", "feature_only", "raw_image", name="cas_data_view"
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "approved",
                "rejected",
                "cancelled",
                "expired",
                "completed",
                name="cas_job_status",
            ),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("policy_version", sa.Integer(), nullable=True),
        sa.Column("signed_manifest", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_cas_ml_job_status_expiry", "cas_ml_jobs", ["status", "expires_at"])

    # 8. cas_job_approvals
    op.create_table(
        "cas_job_approvals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cas_ml_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "approver_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cas_users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "decision",
            sa.Enum("approved", "rejected", "cancelled", name="cas_approval_decision"),
            nullable=False,
        ),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 9. cas_access_audit
    op.create_table(
        "cas_access_audit",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "event_type",
            sa.Enum(
                "login",
                "logout",
                "upload",
                "search",
                "access_request",
                "access_allow",
                "access_deny",
                "decryption",
                "job_create",
                "job_approve",
                "job_reject",
                "job_cancel",
                "policy_create",
                "policy_update",
                "key_rotate",
                "anomaly_alert",
                "audit_verify",
                name="cas_audit_event_type",
            ),
            nullable=False,
        ),
        sa.Column(
            "actor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cas_users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("actor_role", sa.String(length=64), nullable=True),
        sa.Column(
            "envelope_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cas_data_envelopes.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("decision", sa.String(length=64), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column(
            "policy_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cas_policies.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("policy_version", sa.Integer(), nullable=True),
        sa.Column(
            "job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cas_ml_jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("event_hmac", sa.String(length=64), nullable=False),
        sa.Column("prev_event_hmac", sa.String(length=64), nullable=True),
        sa.Column("extra", sa.Text(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_cas_audit_actor_time", "cas_access_audit", ["actor_id", "occurred_at"])
    op.create_index(
        "ix_cas_audit_envelope_time", "cas_access_audit", ["envelope_id", "occurred_at"]
    )
    op.create_index("ix_cas_audit_decision_time", "cas_access_audit", ["decision", "occurred_at"])

    # 10. cas_anomaly_alerts
    op.create_table(
        "cas_anomaly_alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "alert_type",
            sa.Enum(
                "unusual_access_volume",
                "denied_request_spike",
                "raw_data_requests",
                "unusual_access_time",
                "job_failure_spike",
                "excessive_dataset_diversity",
                name="cas_anomaly_type",
            ),
            nullable=False,
        ),
        sa.Column(
            "actor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cas_users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("anomaly_score", sa.Float(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_reviewed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 11. cas_key_versions
    op.create_table(
        "cas_key_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("version_number", sa.Integer(), nullable=False, unique=True),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "rotated_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cas_users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("cas_key_versions")
    op.drop_table("cas_anomaly_alerts")
    op.drop_index("ix_cas_audit_decision_time", table_name="cas_access_audit")
    op.drop_index("ix_cas_audit_envelope_time", table_name="cas_access_audit")
    op.drop_index("ix_cas_audit_actor_time", table_name="cas_access_audit")
    op.drop_table("cas_access_audit")
    op.drop_table("cas_job_approvals")
    op.drop_index("ix_cas_ml_job_status_expiry", table_name="cas_ml_jobs")
    op.drop_table("cas_ml_jobs")
    op.drop_index("ix_cas_protected_index_field_token", table_name="cas_protected_indexes")
    op.drop_table("cas_protected_indexes")
    op.drop_table("cas_data_envelopes")
    op.drop_table("cas_policy_versions")
    op.drop_table("cas_policies")
    op.drop_table("cas_refresh_tokens")
    op.drop_table("cas_users")
