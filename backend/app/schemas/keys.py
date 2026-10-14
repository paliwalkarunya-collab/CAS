"""CAS-SE Key Management Schemas."""

from __future__ import annotations

from pydantic import BaseModel


class RotateResponse(BaseModel):
    old_kek_version: int
    new_kek_version: int
    envelopes_rewrapped: str
