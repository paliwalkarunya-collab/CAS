"""CAS-SE Envelope Schemas."""

from __future__ import annotations

import uuid

from pydantic import BaseModel


class EnvelopeMetadataResponse(BaseModel):
    envelope_id: uuid.UUID
    sensitivity_label: str
    content_type: str | None
    file_size_bytes: int | None
    kek_version: int
    encryption_version: int
    created_at: str
    uploaded_by: uuid.UUID | None = None


class UploadResponse(BaseModel):
    envelope_id: uuid.UUID
    message: str
