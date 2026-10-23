"""
CAS-SE Key Rotation API -- Phase 6
POST /keys/rotate -- Admin-only KEK rotation
GET  /keys        -- KEK version list
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.key_service import KeyServiceAdapter, KeyServiceLockedError
from app.api.auth import require_roles
from app.api.envelopes import get_key_service
from app.db.session import get_db
from app.models.models import CASKeyVersion, CASUser
from app.schemas.keys import (
    KeyStatusResponse,
    RotateResponse,
    ShamirInitResponse,
    ShamirLockResponse,
    ShamirUnlockRequest,
    ShamirUnlockResponse,
)
from app.services.audit import append_audit_event
from app.services.key_management import get_key_versions, rotate_kek

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/status", response_model=KeyStatusResponse)
async def get_key_status(
    _: CASUser = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
    key_service: KeyServiceAdapter = Depends(get_key_service),
) -> KeyStatusResponse:
    """Return non-sensitive status of the active key service adapter."""
    # Synchronize active version from trusted database records if SplitKeyService
    res = await db.execute(
        select(CASKeyVersion.version_number)
        .where(CASKeyVersion.is_current == True)  # noqa: E712
        .order_by(CASKeyVersion.version_number.desc())
    )
    db_cur = res.scalars().first()
    if db_cur is not None and hasattr(key_service, "set_current_version"):
        key_service.set_current_version(db_cur)

    status = key_service.get_status() if hasattr(key_service, "get_status") else {}
    adapter = status.get("adapter", "env")
    is_unlocked = status.get("is_unlocked", True)
    threshold = status.get("threshold", 1)
    total_shares = status.get("total_shares", 1)
    current_version = status.get("current_version", 1)
    shares_provided_count = status.get("shares_provided_count", 1)
    recovered_versions = status.get("recovered_versions", [current_version])

    if db_cur is not None:
        current_version = db_cur

    msg = (
        "Key service is unlocked and ready."
        if is_unlocked
        else f"Key service is LOCKED. Requires {threshold}-of-{total_shares} Shamir shares to unlock."
    )
    return KeyStatusResponse(
        adapter=adapter,
        is_unlocked=is_unlocked,
        threshold=threshold,
        total_shares=total_shares,
        current_version=current_version,
        shares_provided_count=shares_provided_count,
        recovered_versions=recovered_versions,
        message=msg,
    )


@router.post("/shamir/init", response_model=ShamirInitResponse)
async def init_shamir_keys(
    current_user: CASUser = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
    key_service: KeyServiceAdapter = Depends(get_key_service),
) -> ShamirInitResponse:
    """
    Initialize a fresh 256-bit KEK and split it into 2-of-3 threshold shares.

    Administrative bootstrap operation.
    Shares are returned ONCE and must be distributed to independent custodians immediately.
    """
    if not hasattr(key_service, "init_new_key"):
        raise HTTPException(
            status_code=400,
            detail="Active key service is not SplitKeyService. Configure KEY_SERVICE_ADAPTER=split in settings.",
        )

    try:
        version, shares = key_service.init_new_key()
        kcv = getattr(key_service, "get_kcv", lambda v: None)(version)

        # Retire previous versions and ensure version 1 record with cryptographic KCV
        from sqlalchemy import update

        await db.execute(update(CASKeyVersion).values(is_current=False))
        v_check = await db.execute(
            select(CASKeyVersion).where(CASKeyVersion.version_number == version)
        )
        existing_v = v_check.scalar_one_or_none()
        if not existing_v:
            db.add(
                CASKeyVersion(
                    version_number=version,
                    is_current=True,
                    rotated_by=current_user.id,
                    key_check_value=kcv,
                )
            )
        else:
            existing_v.is_current = True
            existing_v.key_check_value = kcv
        await db.flush()

        await append_audit_event(
            db=db,
            event_type="key_rotate",
            actor_id=current_user.id,
            actor_role=current_user.role,
            decision="allow",
            reason=f"Initialized fresh Shamir 2-of-3 key split (v{version})",
        )
        await db.commit()
    except Exception as exc:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail=f"Failed to initialize Shamir keys: {exc}"
        ) from exc

    return ShamirInitResponse(
        version=version,
        threshold=getattr(key_service, "_threshold", 2),
        total_shares=getattr(key_service, "_total", 3),
        shares=shares,
        warning="CRITICAL: Distribute these shares to independent custodians immediately. They will not be displayed again.",
    )


@router.post("/shamir/unlock", response_model=ShamirUnlockResponse)
async def unlock_shamir_keys(
    body: ShamirUnlockRequest,
    current_user: CASUser = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
    key_service: KeyServiceAdapter = Depends(get_key_service),
) -> ShamirUnlockResponse:
    """
    Unlock the SplitKeyService by supplying threshold shares (e.g. 2 of 3).

    Reconstructs the KEK in memory and verifies its Key Check Value (KCV).
    Shares are never persisted or logged.
    """
    if not hasattr(key_service, "unlock"):
        raise HTTPException(
            status_code=400,
            detail="Active key service is not SplitKeyService. Unlock is only applicable in split-key mode.",
        )

    threshold = getattr(key_service, "_threshold", 2)
    if not body.shares or len(body.shares) < threshold:
        raise HTTPException(
            status_code=400,
            detail=f"SplitKeyService requires at least {threshold} shares to reconstruct the KEK; got {len(body.shares) if body.shares else 0}",
        )

    seen_x: set[str] = set()
    for s in body.shares:
        if not isinstance(s, str) or "-" not in s:
            raise HTTPException(
                status_code=400, detail="Malformed split-key share format; expected 'x-hex_y'"
            )
        x_str, _ = s.split("-", 1)
        if x_str in seen_x:
            raise HTTPException(
                status_code=400,
                detail=f"Duplicate share x-coordinate {x_str} detected; shares must be distinct",
            )
        seen_x.add(x_str)

    # 1. Fetch trusted active current version from database
    res_cur = await db.execute(
        select(CASKeyVersion.version_number).where(CASKeyVersion.is_current == True)  # noqa: E712
    )
    db_active_ver = res_cur.scalar_one_or_none()
    if db_active_ver is not None and hasattr(key_service, "set_current_version"):
        key_service.set_current_version(db_active_ver)

    # Check whether any key version records exist in database
    from sqlalchemy import func

    res_count = await db.execute(select(func.count(CASKeyVersion.id)))
    total_db_versions = res_count.scalar_one()

    if total_db_versions == 0:
        target_ver = (
            body.version
            if body.version is not None
            else getattr(key_service, "_current_version", 1)
        )
        expected_kcv = None
    else:
        # 2. Determine target version to unlock
        if body.version is not None:
            target_ver = body.version
            # Verify requested version exists in trusted database records
            res_ver = await db.execute(
                select(CASKeyVersion).where(CASKeyVersion.version_number == target_ver)
            )
            key_ver_record = res_ver.scalar_one_or_none()
            if not key_ver_record:
                await append_audit_event(
                    db=db,
                    event_type="key_rotate",
                    actor_id=current_user.id,
                    actor_role=current_user.role,
                    decision="deny",
                    reason=f"Unlock rejected: Key version {target_ver} does not exist in trusted records",
                )
                await db.commit()
                raise HTTPException(
                    status_code=404,
                    detail=f"Key version {target_ver} does not exist in trusted key-version records.",
                )
        else:
            if db_active_ver is None:
                raise HTTPException(
                    status_code=400,
                    detail="No active current key version found in database. Bootstrap keys first.",
                )
            target_ver = db_active_ver
            res_ver = await db.execute(
                select(CASKeyVersion).where(CASKeyVersion.version_number == target_ver)
            )
            key_ver_record = res_ver.scalar_one_or_none()

        # 3. Enforce KCV requirement - fail closed if missing
        if not key_ver_record or not key_ver_record.key_check_value:
            await append_audit_event(
                db=db,
                event_type="key_rotate",
                actor_id=current_user.id,
                actor_role=current_user.role,
                decision="deny",
                reason=f"Unlock rejected: Key version {target_ver} is missing a required Key Check Value (KCV) commitment",
            )
            await db.commit()
            raise HTTPException(
                status_code=400,
                detail=f"Key version {target_ver} is missing a required Key Check Value (KCV) commitment. Cannot safely unlock.",
            )
        expected_kcv = key_ver_record.key_check_value

    try:
        _, target_version = key_service.unlock(
            body.shares,
            target_ver,
            expected_kcv=expected_kcv,
            require_kcv=(total_db_versions > 0),
        )
        await append_audit_event(
            db=db,
            event_type="key_rotate",
            actor_id=current_user.id,
            actor_role=current_user.role,
            decision="allow",
            reason=f"Shamir KEK v{target_version} unlocked via {len(body.shares)} threshold shares",
        )
        await db.commit()
    except ValueError as exc:
        await append_audit_event(
            db=db,
            event_type="key_rotate",
            actor_id=current_user.id,
            actor_role=current_user.role,
            decision="deny",
            reason=f"Failed Shamir unlock attempt: {exc}",
        )
        await db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return ShamirUnlockResponse(
        unlocked=True,
        version=target_version,
        message=f"KEK v{target_version} successfully reconstructed in memory from threshold shares.",
    )


@router.post("/shamir/lock", response_model=ShamirLockResponse)
async def lock_shamir_keys(
    current_user: CASUser = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
    key_service: KeyServiceAdapter = Depends(get_key_service),
) -> ShamirLockResponse:
    """
    Lock the SplitKeyService, wiping the reconstructed KEK from memory.
    """
    if not hasattr(key_service, "lock"):
        raise HTTPException(
            status_code=400,
            detail="Active key service is not SplitKeyService.",
        )

    key_service.lock()
    await append_audit_event(
        db=db,
        event_type="key_rotate",
        actor_id=current_user.id,
        actor_role=current_user.role,
        decision="allow",
        reason="Shamir KEK locked by administrator -- key material purged from memory",
    )
    await db.commit()

    return ShamirLockResponse(
        locked=True,
        message="SplitKeyService locked successfully. KEK purged from memory.",
    )


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

    If SplitKeyService is active, generates and returns new threshold shares
    for the new KEK version.
    """
    try:
        summary = await rotate_kek(key_service, db, current_user.id)
        if summary.failed_rewraps > 0:
            rewrapped_status = (
                f"Partial rewrap: {summary.successful_rewraps} succeeded, "
                f"{summary.failed_rewraps} failed/skipped. "
                f"Historical keys retained for recovery."
            )
            audit_reason = (
                f"Rotated KEK from v{summary.old_version} to v{summary.new_version} with warnings: "
                f"{summary.successful_rewraps} rewrapped, {summary.failed_rewraps} skipped "
                f"(IDs: {', '.join(summary.skipped_envelope_ids[:5])})"
            )
        else:
            rewrapped_status = (
                f"All {summary.successful_rewraps} DEKs rewrapped successfully -- ciphertext blobs unchanged"
                if summary.successful_rewraps > 0
                else "All DEKs rewrapped -- ciphertext blobs unchanged"
            )
            audit_reason = (
                f"Rotated KEK from version {summary.old_version} to {summary.new_version}"
            )

        await append_audit_event(
            db=db,
            event_type="key_rotate",
            actor_id=current_user.id,
            actor_role=current_user.role,
            decision="allow",
            reason=audit_reason,
            extra={
                "old_version": summary.old_version,
                "new_version": summary.new_version,
                "successful_rewraps": summary.successful_rewraps,
                "failed_rewraps": summary.failed_rewraps,
                "skipped_envelope_ids": summary.skipped_envelope_ids,
            },
        )
        await db.commit()
    except KeyServiceLockedError as exc:
        await append_audit_event(
            db=db,
            event_type="key_rotate",
            actor_id=current_user.id,
            actor_role=current_user.role,
            decision="deny",
            reason="Key rotation blocked: KeyService is locked",
        )
        await db.commit()
        raise HTTPException(
            status_code=503,
            detail="Key service is locked -- 2-of-3 Shamir secret reconstruction required before rotation.",
        ) from exc
    except Exception as exc:
        await append_audit_event(
            db=db,
            event_type="key_rotate",
            actor_id=current_user.id,
            actor_role=current_user.role,
            decision="deny",
            reason=f"Key rotation failed: {exc}",
        )
        await db.commit()
        logger.error("Key rotation failed: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Key rotation failed: {exc}",
        ) from exc

    provisioned_shares = (
        key_service.get_last_generated_shares()
        if hasattr(key_service, "get_last_generated_shares")
        else None
    )

    return RotateResponse(
        old_kek_version=summary.old_version,
        new_kek_version=summary.new_version,
        envelopes_rewrapped=rewrapped_status,
        successful_rewraps=summary.successful_rewraps,
        failed_rewraps=summary.failed_rewraps,
        skipped_envelopes=summary.skipped_envelope_ids,
        provisioned_shares=provisioned_shares,
    )


@router.get("")
async def list_key_versions(
    _: object = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    """List KEK version history (no raw key material returned)."""
    return await get_key_versions(db)
