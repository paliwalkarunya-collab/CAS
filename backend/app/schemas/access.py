"""CAS-SE Access Control Schemas."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field


class AccessRequest(BaseModel):
    envelope_id: uuid.UUID
    purpose: str = Field(min_length=1, max_length=512)
    requested_view: str = Field(pattern="^(metadata_only|masked_image|feature_only|raw_image)$")
    job_id: uuid.UUID | None = None


class AccessResponse(BaseModel):
    decision: str
    reason: str
    allowed_view: str | None
    data_b64: str | None = None  # base64-encoded minimized data (if allowed)
    policy_id: str | None = None
    policy_version: int | None = None
