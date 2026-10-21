"""CAS-SE Policy Management Schemas."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field, computed_field


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

    @computed_field
    def id(self) -> uuid.UUID:
        return self.policy_id

    @computed_field
    def version(self) -> int:
        return self.latest_version


class CreatePolicyRequest(BaseModel):
    name: str = Field(min_length=3, max_length=256)
    description: str | None = None
    rego_policy: str = Field(min_length=10)


class UpdatePolicyRequest(BaseModel):
    description: str | None = None
    rego_policy: str = Field(min_length=10)
    is_active: bool | None = None
