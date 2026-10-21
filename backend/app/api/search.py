"""
CAS-SE Protected Search API -- Phase 4

POST /search -- HMAC-token equality search (no plaintext indexes)

Security notes:
  - Input value is tokenised server-side; the token is used for DB lookup.
  - Plaintext search values are NEVER stored or logged.
  - HMAC tokens are NEVER returned in API responses.
  - Results are filtered through the access policy before being returned.
  - Only approved searchable fields (dataset_id, class_label) are permitted.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.core.config import get_settings
from app.db.session import get_db
from app.models.models import CASDataEnvelope, CASProtectedIndex, CASUser
from app.services.audit import append_audit_event
from app.services.crypto import compute_hmac_token

router = APIRouter()
settings = get_settings()

SEARCHABLE_FIELDS = {"dataset_id", "subject_id", "class_label"}

# Schemas (centralised in app.schemas per PRD §10.3)
from app.schemas.search import SearchRequest, SearchResult  # noqa: E402


async def _execute_protected_search(
    body: SearchRequest,
    current_user: CASUser,
    db: AsyncSession,
) -> list[SearchResult]:
    if body.field_name not in SEARCHABLE_FIELDS:
        await append_audit_event(
            db=db,
            event_type="search",
            actor_id=current_user.id,
            actor_role=current_user.role,
            decision="deny",
            reason=f"Field '{body.field_name}' is not searchable",
        )
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail=f"Field '{body.field_name}' is not a searchable field. "
            f"Permitted: {sorted(SEARCHABLE_FIELDS)}",
        )

    # Compute HMAC token server-side -- never trust client tokens
    token = compute_hmac_token(body.value, settings.index_hmac_key_bytes)

    # Lookup protected index (binary comparison of HMAC token)
    result = await db.execute(
        select(CASProtectedIndex).where(
            CASProtectedIndex.field_name == body.field_name,
            CASProtectedIndex.hmac_token == token,
        )
    )
    indexes = result.scalars().all()

    if not indexes:
        await append_audit_event(
            db=db,
            event_type="search",
            actor_id=current_user.id,
            actor_role=current_user.role,
            decision="allow",
            reason=f"Protected search on field {body.field_name} (0 matches)",
            extra={"field_name": body.field_name, "matches": 0},
        )
        await db.commit()
        return []

    # Fetch envelope metadata for matching indexes
    envelope_ids = [idx.envelope_id for idx in indexes]
    env_result = await db.execute(
        select(CASDataEnvelope).where(CASDataEnvelope.id.in_(envelope_ids))
    )
    envelopes = env_result.scalars().all()

    # Filter: uploaders see only their own envelopes in search results
    if current_user.role == "uploader":
        envelopes = [e for e in envelopes if e.uploaded_by == current_user.id]

    await append_audit_event(
        db=db,
        event_type="search",
        actor_id=current_user.id,
        actor_role=current_user.role,
        decision="allow",
        reason=f"Protected search on field {body.field_name} ({len(envelopes)} matches)",
        extra={"field_name": body.field_name, "matches": len(envelopes)},
    )
    await db.commit()

    # Return metadata only -- NEVER return HMAC tokens, raw data, DEKs, or nonces
    return [
        SearchResult(
            envelope_id=str(e.id),
            sensitivity_label=e.sensitivity_label,
            content_type=e.content_type,
            created_at=e.created_at.isoformat(),
        )
        for e in envelopes
    ]


@router.get("", response_model=list[SearchResult])
async def protected_search_get(
    field: str | None = Query(None, alias="field"),
    field_name: str | None = Query(None, alias="field_name"),
    value: str = Query(..., min_length=1, max_length=1024),
    current_user: CASUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[SearchResult]:
    """Search for envelopes via GET query parameters (as used by frontend / API integration)."""
    resolved_field = field or field_name
    if not resolved_field:
        raise HTTPException(
            status_code=400,
            detail="Missing required query parameter: 'field' (or 'field_name')",
        )
    return await _execute_protected_search(
        SearchRequest(field_name=resolved_field, value=value),
        current_user=current_user,
        db=db,
    )


@router.post("", response_model=list[SearchResult])
async def protected_search(
    body: SearchRequest,
    current_user: CASUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[SearchResult]:
    """
    Search for envelopes using HMAC-protected equality tokens.

    The search value is tokenised server-side -- it is never stored as plaintext
    or used in a LIKE query. The HMAC token is looked up in cas_protected_indexes.

    Known limitation: equality-pattern leakage (see PRD §19).
    """
    return await _execute_protected_search(body, current_user=current_user, db=db)
