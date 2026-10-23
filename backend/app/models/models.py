"""
CAS-SE ORM Models -- Schema Overlay

All tables use the `cas_` prefix to coexist with the organization's
existing database tables without conflict.

Key invariants:
  - UUID primary keys throughout.
  - All timestamps stored as TIMESTAMPTZ (timezone-aware UTC).
  - No raw image payloads -- only encrypted blobs stored in object storage.
  - Alembic manages all DDL -- never use `create_all()` in application code.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import CASBase


def utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Users & Sessions
# ---------------------------------------------------------------------------


class CASUser(CASBase):
    """
    CAS-SE identity record.

    Can federate with the organization's existing user table via a foreign key
    or the IdentityAdapter interface. The `role` field is authoritative here
    and must never be derived from client-supplied claims.
    """

    __tablename__ = "cas_users"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(256), unique=True, nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(
        Enum("admin", "uploader", "trainer", "researcher", "auditor", name="cas_user_role"),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    # Relationships
    refresh_tokens: Mapped[list[CASRefreshToken]] = relationship(
        "CASRefreshToken", back_populates="user", cascade="all, delete-orphan"
    )
    ml_jobs: Mapped[list[CASMLJob]] = relationship(
        "CASMLJob", back_populates="requester", foreign_keys="CASMLJob.requester_id"
    )


class CASRefreshToken(CASBase):
    """Refresh token store for CAS-SE session management with rotation."""

    __tablename__ = "cas_refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("cas_users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[CASUser] = relationship("CASUser", back_populates="refresh_tokens")


# ---------------------------------------------------------------------------
# Data Envelopes & Protected Search Indexes
# ---------------------------------------------------------------------------


class CASDataEnvelope(CASBase):
    """
    Encrypted data envelope metadata.

    The encrypted ciphertext is stored in object storage (via StorageAdapter).
    The RDBMS stores ONLY metadata -- never raw data bytes or decrypted content.
    """

    __tablename__ = "cas_data_envelopes"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Object storage reference -- randomised key, never original filename
    object_uri: Mapped[str] = mapped_column(String(1024), nullable=False, unique=True)
    # AES-GCM nonce (12 bytes, hex-encoded)
    nonce_hex: Mapped[str] = mapped_column(String(24), nullable=False)
    # DEK wrapped with KEK -- stored as base64
    wrapped_dek: Mapped[str] = mapped_column(Text, nullable=False)
    # Version of KEK used to wrap the DEK
    kek_version: Mapped[int] = mapped_column(Integer, nullable=False)
    # SHA-256 hash of ciphertext for integrity verification
    ciphertext_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # Sensitivity label (e.g., "restricted", "confidential")
    sensitivity_label: Mapped[str] = mapped_column(String(64), nullable=False, default="restricted")
    # Deprecated legacy plaintext field. New records use dataset_scope_token.
    dataset_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    dataset_scope_token: Mapped[str | None] = mapped_column(String(96), nullable=True, index=True)
    # Original filename hash only (never original filename)
    filename_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Content type
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # File size in bytes
    file_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Encryption version for algorithm agility
    encryption_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # Uploader reference
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("cas_users.id", ondelete="SET NULL"), nullable=True
    )
    # Active policy at time of upload
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("cas_policies.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    # Relationships
    protected_indexes: Mapped[list[CASProtectedIndex]] = relationship(
        "CASProtectedIndex", back_populates="envelope", cascade="all, delete-orphan"
    )
    audit_events: Mapped[list[CASAccessAudit]] = relationship(
        "CASAccessAudit", back_populates="envelope"
    )


class CASProtectedIndex(CASBase):
    """
    HMAC-SHA-256 protected equality-search tokens.

    Enables searching for records by indexed field values without storing
    those values in plaintext. The HMAC token is computed as:
        HMAC-SHA-256(index_hmac_key, normalize(field_value))

    Known limitation: equality-pattern leakage -- see PRD §19.
    """

    __tablename__ = "cas_protected_indexes"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    envelope_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("cas_data_envelopes.id", ondelete="CASCADE"),
        nullable=False,
    )
    field_name: Mapped[str] = mapped_column(String(128), nullable=False)
    hmac_token: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    envelope: Mapped[CASDataEnvelope] = relationship(
        "CASDataEnvelope", back_populates="protected_indexes"
    )

    __table_args__ = (
        UniqueConstraint(
            "field_name",
            "token_version",
            "hmac_token",
            "envelope_id",
            name="uq_cas_protected_index",
        ),
        Index("ix_cas_protected_index_field_token", "field_name", "hmac_token"),
    )


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


class CASPolicy(CASBase):
    """Access policy definition (evaluated by OPA)."""

    __tablename__ = "cas_policies"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    rego_policy: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("cas_users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    versions: Mapped[list[CASPolicyVersion]] = relationship(
        "CASPolicyVersion", back_populates="policy", cascade="all, delete-orphan"
    )


class CASPolicyVersion(CASBase):
    """Immutable, versioned snapshot of a policy at a point in time."""

    __tablename__ = "cas_policy_versions"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    policy_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("cas_policies.id", ondelete="CASCADE"),
        nullable=False,
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    rego_snapshot: Mapped[str] = mapped_column(Text, nullable=False)
    snapshot_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    policy: Mapped[CASPolicy] = relationship("CASPolicy", back_populates="versions")

    __table_args__ = (
        UniqueConstraint("policy_id", "version_number", name="uq_cas_policy_version"),
    )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class CASAccessAudit(CASBase):
    """
    Hash-chained, tamper-evident audit event.

    Fields are canonicalized before HMAC computation to prevent
    format-manipulation attacks. The chain links each event to the previous
    event's HMAC, forming a tamper-evident sequence.

    The `prev_event_hmac` is NULL only for the first event in the chain.
    """

    __tablename__ = "cas_access_audit"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    event_type: Mapped[str] = mapped_column(
        Enum(
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
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("cas_users.id", ondelete="SET NULL"), nullable=True
    )
    actor_role: Mapped[str | None] = mapped_column(String(64), nullable=True)
    envelope_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("cas_data_envelopes.id", ondelete="SET NULL"),
        nullable=True,
    )
    decision: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("cas_policies.id", ondelete="SET NULL"), nullable=True
    )
    policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("cas_ml_jobs.id", ondelete="SET NULL"), nullable=True
    )
    # HMAC of this event's canonical fields
    event_hmac: Mapped[str] = mapped_column(String(64), nullable=False)
    # HMAC of the previous event (null for first event)
    prev_event_hmac: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Extra context (JSON -- must not contain secrets or raw data)
    extra: Mapped[str | None] = mapped_column(Text, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    envelope: Mapped[CASDataEnvelope | None] = relationship(
        "CASDataEnvelope", back_populates="audit_events"
    )

    __table_args__ = (
        Index("ix_cas_audit_actor_time", "actor_id", "occurred_at"),
        Index("ix_cas_audit_envelope_time", "envelope_id", "occurred_at"),
        Index("ix_cas_audit_decision_time", "decision", "occurred_at"),
    )


# ---------------------------------------------------------------------------
# ML Jobs
# ---------------------------------------------------------------------------


class CASMLJob(CASBase):
    """
    Scoped ML / research job request.

    Access to data is bound to active, approved, unexpired jobs.
    The signed manifest is generated on approval and contains the
    exact envelope IDs and data view permitted.
    """

    __tablename__ = "cas_ml_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    requester_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("cas_users.id", ondelete="RESTRICT"), nullable=False
    )
    purpose: Mapped[str] = mapped_column(String(512), nullable=False)
    dataset_scope: Mapped[str] = mapped_column(
        Text, nullable=False
    )  # JSON array of protected tokens
    requested_view: Mapped[str] = mapped_column(
        Enum("metadata_only", "masked_image", "feature_only", "raw_image", name="cas_data_view"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        Enum(
            "pending",
            "approved",
            "rejected",
            "cancelled",
            "expired",
            "completed",
            name="cas_job_status",
        ),
        nullable=False,
        default="pending",
    )
    policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Signed manifest JSON (generated on approval)
    signed_manifest: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    requester: Mapped[CASUser] = relationship(
        "CASUser", back_populates="ml_jobs", foreign_keys=[requester_id]
    )
    approvals: Mapped[list[CASJobApproval]] = relationship(
        "CASJobApproval", back_populates="job", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_cas_ml_job_status_expiry", "status", "expires_at"),)


class CASJobApproval(CASBase):
    """Admin approval or rejection record for an ML job."""

    __tablename__ = "cas_job_approvals"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("cas_ml_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    approver_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("cas_users.id", ondelete="RESTRICT"), nullable=False
    )
    decision: Mapped[str] = mapped_column(
        Enum("approved", "rejected", "cancelled", name="cas_approval_decision"),
        nullable=False,
    )
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    job: Mapped[CASMLJob] = relationship("CASMLJob", back_populates="approvals")


# ---------------------------------------------------------------------------
# Anomaly Alerts
# ---------------------------------------------------------------------------


class CASAnomalyAlert(CASBase):
    """IsolationForest anomaly detection alert derived from audit events."""

    __tablename__ = "cas_anomaly_alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    alert_type: Mapped[str] = mapped_column(
        Enum(
            "unusual_access_volume",
            "denied_request_spike",
            "raw_data_requests",
            "unusual_access_time",
            "job_failure_spike",
            "excessive_dataset_diversity",
            name="cas_anomaly_type",
        ),
        nullable=False,
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("cas_users.id", ondelete="SET NULL"), nullable=True
    )
    anomaly_score: Mapped[float | None] = mapped_column(nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_reviewed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


# ---------------------------------------------------------------------------
# Key Versions
# ---------------------------------------------------------------------------


class CASKeyVersion(CASBase):
    """
    KEK version tracking for envelope-encryption rotation.

    Does NOT store raw key material -- only metadata about the version.
    The actual KEK is sourced from the configured KeyServiceAdapter (KMS/Vault/env).
    """

    __tablename__ = "cas_key_versions"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
    is_current: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    rotated_by: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("cas_users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    key_check_value: Mapped[str | None] = mapped_column(String(64), nullable=True)
