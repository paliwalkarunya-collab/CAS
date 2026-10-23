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

import logging
import uuid
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.key_service import KeyServiceAdapter
from app.core.config import get_settings
from app.models.models import CASDataEnvelope, CASKeyVersion
from app.services.crypto import unwrap_dek, wrap_dek

logger = logging.getLogger(__name__)
settings = get_settings()


class RotationSummary(tuple[int, int]):
    """
    Summary of key rotation execution.
    Subclasses 2-tuple for backwards compatibility with `old_v, new_v = rotate_kek(...)`.
    """

    old_version: int
    new_version: int
    successful_rewraps: int
    failed_rewraps: int
    skipped_envelope_ids: list[str]

    def __new__(
        cls,
        old_version: int,
        new_version: int,
        successful_rewraps: int = 0,
        failed_rewraps: int = 0,
        skipped_envelope_ids: list[str] | None = None,
    ) -> RotationSummary:
        instance = super().__new__(cls, (old_version, new_version))
        instance.old_version = old_version
        instance.new_version = new_version
        instance.successful_rewraps = successful_rewraps
        instance.failed_rewraps = failed_rewraps
        instance.skipped_envelope_ids = skipped_envelope_ids or []
        return instance


async def rotate_kek(
    key_service: KeyServiceAdapter,
    db: AsyncSession,
    rotated_by: uuid.UUID,
) -> RotationSummary:
    """
    Rotate the Key Encryption Key and rewrap all stored DEKs.

    Steps:
      1. Get current KEK (to unwrap existing DEKs).
      2. Generate new KEK via the key service adapter.
      3. For every envelope not on the new version: unwrap DEK with old KEK, rewrap with new KEK.
      4. Update envelope records with new wrapped DEKs and kek_version.
      5. Record the new KEK version in cas_key_versions.
      6. Retire old versions that no longer have any active envelopes.

    :returns: RotationSummary(old_version, new_version, successful_rewraps, failed_rewraps, skipped_envelope_ids)
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

    # Align key service with highest known DB version if adapter supports set_current_version
    max_ver_res = await db.execute(select(func.max(CASKeyVersion.version_number)))
    max_db_ver = max_ver_res.scalar_one_or_none()
    if max_db_ver is not None and hasattr(key_service, "set_current_version"):
        if max_db_ver > key_service.current_kek_version():
            key_service.set_current_version(max_db_ver)

    # 2. Rotate and normalize the legacy reference adapter's return shape.
    rotation_result = key_service.rotate_kek()
    new_version = rotation_result if isinstance(rotation_result, int) else rotation_result[1]

    # 3 & 4. Rewrap all DEKs not yet on the new version
    result = await db.execute(
        select(CASDataEnvelope).where(CASDataEnvelope.kek_version != new_version)
    )
    envelopes = result.scalars().all()

    successful_rewraps = 0
    failed_rewraps = 0
    skipped_envelope_ids: list[str] = []

    for envelope in envelopes:
        try:
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
            successful_rewraps += 1
        except Exception as exc:
            failed_rewraps += 1
            skipped_envelope_ids.append(str(envelope.id))
            logger.warning(
                "Skipping envelope %s during rewrap: unable to unwrap under KEK v%s (%s). "
                "Envelope remains encrypted under historical key v%s.",
                envelope.id,
                envelope.kek_version,
                exc,
                envelope.kek_version,
            )
    await db.flush()

    # 5. Record new version with Key Check Value (KCV) commitment (upsert to avoid collision)
    kcv = getattr(key_service, "get_kcv", lambda v: None)(new_version)
    existing_ver_res = await db.execute(
        select(CASKeyVersion).where(CASKeyVersion.version_number == new_version)
    )
    existing_ver = existing_ver_res.scalar_one_or_none()
    if existing_ver is not None:
        existing_ver.is_current = True
        existing_ver.retired_at = None
        existing_ver.rotated_by = rotated_by
        existing_ver.key_check_value = kcv
    else:
        key_version_record = CASKeyVersion(
            id=uuid.uuid4(),
            version_number=new_version,
            is_current=True,
            rotated_by=rotated_by,
            key_check_value=kcv,
        )
        db.add(key_version_record)
    await db.flush()

    # 6. Retire old versions, BUT DO NOT retire any key version that is still
    # needed by an envelope that failed or was skipped during rewrap!
    active_env_versions_res = await db.execute(
        select(CASDataEnvelope.kek_version).distinct()
    )
    still_needed_versions = set(active_env_versions_res.scalars().all())

    old_versions_res = await db.execute(
        select(CASKeyVersion).where(CASKeyVersion.version_number != new_version)
    )
    for old_v in old_versions_res.scalars().all():
        old_v.is_current = False
        if old_v.version_number not in still_needed_versions:
            if old_v.retired_at is None:
                old_v.retired_at = datetime.now(UTC)
        else:
            # Envelope(s) still rely on this version: preserve as unretired
            old_v.retired_at = None
    await db.flush()

    return RotationSummary(
        old_version=current_version,
        new_version=new_version,
        successful_rewraps=successful_rewraps,
        failed_rewraps=failed_rewraps,
        skipped_envelope_ids=skipped_envelope_ids,
    )


async def get_key_versions(db: AsyncSession) -> list[dict[str, Any]]:
    """Return all tracked KEK versions (no raw key material)."""
    result = await db.execute(select(CASKeyVersion).order_by(CASKeyVersion.version_number.asc()))
    versions = result.scalars().all()
    if not versions:
        return [
            {
                "version_number": settings.cas_kek_current_version,
                "is_current": True,
                "created_at": datetime.now(UTC).isoformat(),
                "retired_at": None,
            }
        ]
    return [
        {
            "version_number": v.version_number,
            "is_current": v.is_current,
            "created_at": v.created_at.isoformat(),
            "retired_at": v.retired_at.isoformat() if v.retired_at else None,
        }
        for v in versions
    ]
