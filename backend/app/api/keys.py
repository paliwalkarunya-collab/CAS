"""
CAS-SE Key Rotation API -- Phase 6
POST /keys/rotate -- Admin-only KEK rotation
GET  /keys        -- KEK version list
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.key_service import KeyServiceAdapter
from app.api.auth import require_roles
from app.api.envelopes import get_key_service
from app.db.session import get_db
from app.models.models import CASUser
from app.services.audit import append_audit_event
from app.services.key_management import get_key_versions, rotate_kek

router = APIRouter()

# Schemas (centralised in app.schemas per PRD §10.3)
from app.schemas.keys import RotateResponse  # noqa: E402


@router.post("/rotate", response_model=RotateResponse)
async def rotate_key(
    current_user: CASUser = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
    key_service: KeyServiceAdapter = Depends(get_key_service),
) -> RotateResponse:
    """
    Rotate the Key Encryption Key.

    Rewraps all stored DEKs with the new KEK version WITHOUT re-encrypting
    the stored ciphertext blobs. Admin-only operation. Fully audited.

    Note: Raw KEK material is NEVER returned in this response.
    """
    try:
        old_version, new_version = await rotate_kek(key_service, db, current_user.id)
        await append_audit_event(
            db=db,
            event_type="key_rotate",
            actor_id=current_user.id,
            actor_role=current_user.role,
            decision="allow",
            reason=f"Rotated KEK from version {old_version} to {new_version}",
        )
        await db.commit()
    except Exception as exc:
        await append_audit_event(
            db=db,
            event_type="key_rotate",
            actor_id=current_user.id,
            actor_role=current_user.role,
            decision="deny",
            reason="Key rotation failed",
        )
        await db.commit()
        raise HTTPException(
            status_code=500,
            detail="Key rotation failed",
        ) from exc

    return RotateResponse(
        old_kek_version=old_version,
        new_kek_version=new_version,
        envelopes_rewrapped="All DEKs rewrapped -- ciphertext blobs unchanged",
    )


@router.get("")
async def list_key_versions(
    _: object = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    """List KEK version history (no raw key material returned)."""
    return await get_key_versions(db)
