"""CAS-SE Protected Search Schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SearchRequest(BaseModel):
    field_name: str = Field(min_length=1, max_length=128)
    value: str = Field(min_length=1, max_length=1024)


class SearchResult(BaseModel):
    envelope_id: str
    sensitivity_label: str
    content_type: str | None
    created_at: str
