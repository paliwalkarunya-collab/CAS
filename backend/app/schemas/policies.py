"""CAS-SE Policy Management Schemas."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field


class PolicyVersionResponse(BaseModel):
    version_number: int
    snapshot_hash: str
    created_at: str


class PolicyResponse(BaseModel):
    policy_id: uuid.UUID
    name: str
    description: str | None
    is_active: bool
    rego_policy: str
    latest_version: int
    created_at: str
    updated_at: str


class CreatePolicyRequest(BaseModel):
    name: str = Field(min_length=3, max_length=256)
    description: str | None = None
    rego_policy: str = Field(min_length=10)


class UpdatePolicyRequest(BaseModel):
    description: str | None = None
    rego_policy: str = Field(min_length=10)
    is_active: bool | None = None
