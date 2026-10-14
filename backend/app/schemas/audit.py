"""CAS-SE Audit and Anomaly Schemas."""

from __future__ import annotations

import uuid

from pydantic import BaseModel


class AuditEventResponse(BaseModel):
    event_id: uuid.UUID
    event_type: str
    actor_id: uuid.UUID | None
    actor_role: str | None
    envelope_id: uuid.UUID | None
    decision: str | None
    reason: str | None
    job_id: uuid.UUID | None
    occurred_at: str
    # event_hmac is intentionally omitted from API responses -- auditors use /verify


class ChainVerifyResponse(BaseModel):
    is_valid: bool
    message: str
    events_verified: int


class CheckpointResponse(BaseModel):
    last_event_id: uuid.UUID | None
    last_event_hmac: str | None
    total_events: int
    checkpoint_timestamp: str
    checkpoint_signature: str


class AnomalyAlertResponse(BaseModel):
    alert_id: uuid.UUID
    alert_type: str
    actor_id: uuid.UUID | None
    anomaly_score: float | None
    description: str | None
    is_reviewed: bool
    detected_at: str


class RunAnomaliesResponse(BaseModel):
    status: str
    alerts_created: int
