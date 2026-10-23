"""
CAS-SE Envelope API -- Phase 3

POST /envelopes -- Encrypted ingestion endpoint
GET  /envelopes -- Policy-filtered metadata list
GET  /envelopes/{id} -- Single envelope metadata
"""

from __future__ import annotations

import logging
import uuid
from typing import cast

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.factory import AdapterConfigurationError, build_key_service, build_storage_adapter
from app.adapters.key_service import KeyServiceAdapter, KeyServiceLockedError
from app.adapters.storage import StorageAdapter, generate_object_key
from app.api.auth import get_current_user, require_roles
from app.core.config import get_settings
from app.db.session import get_db
from app.models.models import CASDataEnvelope, CASProtectedIndex, CASUser
from app.schemas.envelopes import EnvelopeMetadataResponse, UploadResponse
from app.services.crypto import compute_hmac_token, encode_scope_token, sha256_hex
from app.services.envelope import (
    build_protected_indexes,
    ingest_record,
    validate_upload,
)

logger = logging.getLogger("cas_se.envelopes")
router = APIRouter()
settings = get_settings()

# ---------------------------------------------------------------------------
# Helper: get configured storage adapter and key service
# ---------------------------------------------------------------------------


def get_storage_adapter(request: Request) -> StorageAdapter:
    """Return the application-scoped, configured ciphertext-storage adapter."""
    adapter = request.app.state.cas_storage_adapter
    if adapter is None:
        try:
            adapter = build_storage_adapter(settings)
        except AdapterConfigurationError as exc:
            raise RuntimeError("CAS-SE storage adapter configuration is invalid") from exc
        request.app.state.cas_storage_adapter = adapter
    return cast(StorageAdapter, adapter)


def get_key_service(request: Request) -> KeyServiceAdapter:
    """Return the application-scoped, configured versioned KEK adapter."""
    adapter = request.app.state.cas_key_service
    if adapter is None:
        try:
            adapter = build_key_service(settings)
        except AdapterConfigurationError as exc:
            raise RuntimeError("CAS-SE key-service adapter configuration is invalid") from exc
        request.app.state.cas_key_service = adapter
    return cast(KeyServiceAdapter, adapter)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("", response_model=UploadResponse, status_code=201)
async def create_envelope(
    file: UploadFile = File(...),
    dataset_id: str | None = Form(None, max_length=256),
    class_label: str | None = Form(None, max_length=256),
    subject_id: str | None = Form(None, max_length=256),
    sensitivity_label: str = Form("restricted", max_length=64),
    current_user: CASUser = Depends(require_roles("admin", "uploader")),
    db: AsyncSession = Depends(get_db),
    storage: StorageAdapter = Depends(get_storage_adapter),
    key_service: KeyServiceAdapter = Depends(get_key_service),
) -> UploadResponse:
    """
    Encrypt and ingest a data record.

    The encrypted ciphertext is stored in object storage.
    The RDBMS receives only envelope metadata -- never raw data bytes.

    Requires: admin or uploader role.
    Audited: every attempt (success and failure).
    """
    from app.services.audit import append_audit_event

    data = await file.read()
    filename = file.filename or "upload"

    # 1. Validate
    validation = validate_upload(filename, data)
    if not validation.is_valid:
        await append_audit_event(
            db=db,
            event_type="upload",
            actor_id=current_user.id,
            actor_role=current_user.role,
            decision="deny",
            reason=validation.error,
        )
        await db.commit()
        raise HTTPException(status_code=422, detail=validation.error)

    try:
        # 2. Generate envelope ID and object key
        envelope_id = uuid.uuid4()
        object_key = generate_object_key("envelopes")

        # 3. Get KEK
        # 4. Encrypt and store. The core flow calls the adapter's wrap operation
        # so an enterprise KMS/HSM implementation never exports its KEK.
        result = ingest_record(
            plaintext=data,
            envelope_id=envelope_id,
            policy_id=None,  # Default policy -- will be resolved in Phase 4
            sensitivity_label=sensitivity_label,
            kek=b"",
            kek_version=0,
            object_key=object_key,
            storage_adapter=storage,
            key_service=key_service,
        )

        # 5. Persist envelope metadata (NOT the raw data)
        filename_hash = sha256_hex(filename.encode())
        envelope = CASDataEnvelope(
            id=envelope_id,
            object_uri=result.object_uri,
            nonce_hex=result.nonce_hex,
            wrapped_dek=result.wrapped_dek_b64,
            kek_version=result.kek_version,
            ciphertext_hash=result.ciphertext_sha256,
            sensitivity_label=result.sensitivity_label,
            encryption_version=result.encryption_version,
            # Scope matching is performed with a protected token; plaintext
            # dataset identifiers are neither returned nor persisted for new records.
            dataset_id=None,
            dataset_scope_token=(
                encode_scope_token(compute_hmac_token(dataset_id, settings.index_hmac_key_bytes))
                if dataset_id
                else None
            ),
            filename_hash=filename_hash,
            content_type=validation.content_type,
            file_size_bytes=validation.file_size_bytes,
            uploaded_by=current_user.id,
        )
        db.add(envelope)
        await db.flush()

        # 6. Create HMAC protected indexes
        field_values: dict[str, str] = {}
        if dataset_id:
            field_values["dataset_id"] = dataset_id
        if class_label:
            field_values["class_label"] = class_label
        if subject_id:
            field_values["subject_id"] = subject_id

        if field_values:
            tokens = build_protected_indexes(field_values, settings.index_hmac_key_bytes)
            for field_name, token in tokens.items():
                index = CASProtectedIndex(
                    id=uuid.uuid4(),
                    envelope_id=envelope_id,
                    field_name=field_name,
                    hmac_token=token,
                )
                db.add(index)
            await db.flush()

        # 7. Audit success
        await append_audit_event(
            db=db,
            event_type="upload",
            actor_id=current_user.id,
            actor_role=current_user.role,
            envelope_id=envelope_id,
            decision="allow",
            reason="Uploaded and encrypted successfully",
        )
        await db.commit()

        return UploadResponse(
            envelope_id=envelope_id,
            message="Record encrypted and stored successfully",
        )
    except HTTPException:
        raise
    except KeyServiceLockedError as exc:
        await db.rollback()
        try:
            await append_audit_event(
                db=db,
                event_type="upload",
                actor_id=current_user.id,
                actor_role=current_user.role,
                decision="deny",
                reason="Upload blocked: KeyService is locked",
            )
            await db.commit()
        except Exception:
            await db.rollback()
        raise HTTPException(
            status_code=503,
            detail="Key service is locked -- Shamir secret reconstruction required before data ingestion.",
        ) from exc
    except Exception as exc:
        logger.exception("Upload and encryption failed: %s", exc)
        await db.rollback()
        try:
            await append_audit_event(
                db=db,
                event_type="upload",
                actor_id=current_user.id,
                actor_role=current_user.role,
                decision="deny",
                reason="Upload encryption or storage failed",
            )
            await db.commit()
        except Exception:
            await db.rollback()
        raise HTTPException(status_code=500, detail="Upload and encryption failed") from exc


@router.get("", response_model=list[EnvelopeMetadataResponse])
async def list_envelopes(
    current_user: CASUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[EnvelopeMetadataResponse]:
    """
    List envelope metadata (policy-filtered).

    Uploaders see their own uploads. Admins and auditors see all.
    Raw data, DEKs, nonces, and HMAC tokens are NEVER returned.
    """
    query = select(CASDataEnvelope).order_by(CASDataEnvelope.created_at.desc())

    # Non-admins/auditors see only their own uploads
    if current_user.role not in ("admin", "auditor"):
        query = query.where(CASDataEnvelope.uploaded_by == current_user.id)

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    envelopes = result.scalars().all()

    return [
        EnvelopeMetadataResponse(
            envelope_id=e.id,
            sensitivity_label=e.sensitivity_label,
            content_type=e.content_type,
            file_size_bytes=e.file_size_bytes,
            kek_version=e.kek_version,
            encryption_version=e.encryption_version,
            created_at=e.created_at.isoformat(),
            uploaded_by=e.uploaded_by,
        )
        for e in envelopes
    ]


@router.get("/{envelope_id}", response_model=EnvelopeMetadataResponse)
async def get_envelope(
    envelope_id: uuid.UUID,
    current_user: CASUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EnvelopeMetadataResponse:
    """
    Get a single envelope's metadata.

    Returns metadata only -- use /access-request (Phase 4) to request data access.
    """
    result = await db.execute(select(CASDataEnvelope).where(CASDataEnvelope.id == envelope_id))
    envelope = result.scalar_one_or_none()
    if not envelope:
        raise HTTPException(status_code=404, detail="Envelope not found")

    # Non-admins/auditors can only view their own envelopes
    if current_user.role not in ("admin", "auditor") and envelope.uploaded_by != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    return EnvelopeMetadataResponse(
        envelope_id=envelope.id,
        sensitivity_label=envelope.sensitivity_label,
        content_type=envelope.content_type,
        file_size_bytes=envelope.file_size_bytes,
        kek_version=envelope.kek_version,
        encryption_version=envelope.encryption_version,
        created_at=envelope.created_at.isoformat(),
        uploaded_by=envelope.uploaded_by,
    )
