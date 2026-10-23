"""CAS-SE Key Management Schemas."""

from __future__ import annotations

from pydantic import BaseModel


class RotateResponse(BaseModel):
    old_kek_version: int
    new_kek_version: int
    envelopes_rewrapped: str
    successful_rewraps: int = 0
    failed_rewraps: int = 0
    skipped_envelopes: list[str] = []
    provisioned_shares: list[str] | None = None


class KeyStatusResponse(BaseModel):
    adapter: str
    is_unlocked: bool
    threshold: int
    total_shares: int
    current_version: int
    shares_provided_count: int
    recovered_versions: list[int]
    message: str


class ShamirUnlockRequest(BaseModel):
    shares: list[str]
    version: int | None = None


class ShamirUnlockResponse(BaseModel):
    unlocked: bool
    version: int
    message: str


class ShamirInitResponse(BaseModel):
    version: int
    threshold: int
    total_shares: int
    shares: list[str]
    warning: str


class ShamirLockResponse(BaseModel):
    locked: bool
    message: str
