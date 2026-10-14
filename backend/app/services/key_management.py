"""
CAS-SE Key Management Service -- Phase 6

Handles:
  1. KEK versioning and rotation via the KeyServiceAdapter
  2. DEK rewrapping on rotation (without re-encrypting stored ciphertext)
  3. Split-key simulation documentation

Invariant: Rotation rewraps DEKs only -- stored ciphertext blobs are never touched.
           The payload decryption key (DEK) changes its wrapper, not its content.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.key_service import KeyServiceAdapter
from app.core.config import get_settings
from app.models.models import CASDataEnvelope, CASKeyVersion
from app.services.crypto import unwrap_dek, wrap_dek

settings = get_settings()


async def rotate_kek(
    key_service: KeyServiceAdapter,
    db: AsyncSession,
    rotated_by: uuid.UUID,
) -> tuple[int, int]:
    """
    Rotate the Key Encryption Key and rewrap all stored DEKs.

    Steps:
      1. Get current KEK (to unwrap existing DEKs).
      2. Generate new KEK via the key service adapter.
      3. For every envelope: unwrap DEK with old KEK, rewrap with new KEK.
      4. Update envelope records with new wrapped DEKs and kek_version.
      5. Record the new KEK version in cas_key_versions.
      6. Retire the old version.

    :returns: (old_version, new_version)
    :raises: Any exception from the key service adapter propagates up.
    """
    # 1. Current key reference. The service never asks a production adapter
    # for master-key bytes; KMS/HSM adapters perform wrap/unwrap internally.
    legacy_service = cast(Any, key_service)
    current_version = (
        key_service.current_kek_version()
        if hasattr(key_service, "current_kek_version")
        else legacy_service.get_current_kek()[1]
    )

    # 2. Rotate and normalize the legacy reference adapter's return shape.
    rotation_result = key_service.rotate_kek()
    new_version = rotation_result if isinstance(rotation_result, int) else rotation_result[1]

    # 3 & 4. Rewrap all DEKs
    result = await db.execute(
        select(CASDataEnvelope).where(CASDataEnvelope.kek_version == current_version)
    )
    envelopes = result.scalars().all()

    for envelope in envelopes:
        if hasattr(key_service, "unwrap_dek") and hasattr(key_service, "wrap_dek"):
            old_dek = key_service.unwrap_dek(envelope.wrapped_dek, envelope.kek_version)
            wrapped_dek, wrapped_version = key_service.wrap_dek(old_dek)
            envelope.wrapped_dek = wrapped_dek
            envelope.kek_version = wrapped_version
        else:
            old_kek = legacy_service.get_kek_by_version(envelope.kek_version)
            old_dek = unwrap_dek(envelope.wrapped_dek, old_kek)
            new_kek = legacy_service.get_kek_by_version(new_version)
            wrapped = wrap_dek(old_dek, new_kek, new_version)
            envelope.wrapped_dek = wrapped.wrapped_dek_b64
            envelope.kek_version = wrapped.kek_version
    await db.flush()

    # 5. Record new version
    key_version_record = CASKeyVersion(
        id=uuid.uuid4(),
        version_number=new_version,
        is_current=True,
        rotated_by=rotated_by,
    )
    db.add(key_version_record)

    # 6. Retire old version
    await db.execute(
        update(CASKeyVersion)
        .where(CASKeyVersion.version_number == current_version)
        .values(is_current=False, retired_at=datetime.now(UTC))
    )
    await db.flush()

    return current_version, new_version


async def get_key_versions(db: AsyncSession) -> list[dict[str, Any]]:
    """Return all tracked KEK versions (no raw key material)."""
    result = await db.execute(select(CASKeyVersion).order_by(CASKeyVersion.version_number.asc()))
    versions = result.scalars().all()
    return [
        {
            "version_number": v.version_number,
            "is_current": v.is_current,
            "created_at": v.created_at.isoformat(),
            "retired_at": v.retired_at.isoformat() if v.retired_at else None,
        }
        for v in versions
    ]
