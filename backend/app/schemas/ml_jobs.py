"""CAS-SE ML Job Workflow Schemas."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field


class CreateJobRequest(BaseModel):
    purpose: str = Field(min_length=10, max_length=512)
    dataset_scope: list[str] = Field(min_length=1)
    requested_view: str = Field(pattern="^(metadata_only|masked_image|feature_only|raw_image)$")
    duration_hours: int = Field(ge=1, le=720, default=24)


class ApproveJobRequest(BaseModel):
    reason: str | None = None


class RejectJobRequest(BaseModel):
    reason: str


class MLJobResponse(BaseModel):
    job_id: uuid.UUID
    requester_id: uuid.UUID
    purpose: str
    dataset_scope: list[str]
    requested_view: str
    status: str
    created_at: str
    expires_at: str


class JobManifest(BaseModel):
    job_id: str
    requester_id: str
    allowed_view: str
    envelope_ids: list[str]
    expires_at: str
    policy_version: int | None
