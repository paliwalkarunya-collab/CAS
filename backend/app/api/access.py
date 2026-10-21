"""
CAS-SE Access Request API -- Phase 4

POST /access-request -- Context evaluation -> OPA decision -> minimized data release

Every access request:
  1. Verifies JWT + resolves role from DB (not JWT payload)
  2. Loads envelope metadata
  3. Validates ML job (if required)
  4. Calls OPA with full context (identity, resource, job state)
  5. On DENY: returns 403 with reason (no data)
  6. On ALLOW: decrypts and minimizes data, returns permitted view
  7. Audit events for every attempt

Security: OPA unavailability -> deny. Expired job -> deny. Scope mismatch -> deny.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.key_service import KeyServiceAdapter
from app.adapters.storage import StorageAdapter
from app.api.auth import get_current_user
from app.api.envelopes import get_key_service, get_storage_adapter
from app.core.config import get_settings
from app.core.rate_limit import limiter
from app.db.session import get_db
from app.models.models import CASDataEnvelope, CASMLJob, CASUser
from app.policy.opa_client import evaluate_access_policy
from app.services.audit import append_audit_event
from app.services.crypto import compute_hmac_token, encode_scope_token
from app.services.envelope import minimize_data, retrieve_and_decrypt
from app.services.manifest import ManifestVerificationError, verify_signed_manifest

router = APIRouter()
settings = get_settings()

# Schemas (centralised in app.schemas per PRD §10.3)
from app.schemas.access import AccessRequest, AccessResponse  # noqa: E402


@router.post("", response_model=AccessResponse)
@limiter.limit(settings.rate_limit_access_request)
async def access_request(
    request: Request,
    body: AccessRequest,
    current_user: CASUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    storage: StorageAdapter = Depends(get_storage_adapter),
    key_service: KeyServiceAdapter = Depends(get_key_service),
) -> AccessResponse:
    """
    Request access to a data record with full context evaluation.

    The OPA policy evaluates: identity, role, purpose, requested view,
    resource sensitivity, dataset scope, job approval status, and expiry.

    Returns a minimized data view (or deny) based on the policy decision.
    """
    # 1. Load envelope
    env_result = await db.execute(
        select(CASDataEnvelope).where(CASDataEnvelope.id == body.envelope_id)
    )
    envelope = env_result.scalar_one_or_none()
    if not envelope:
        raise HTTPException(status_code=404, detail="Envelope not found")

    # 2. Load ML job context (if provided)
    job_context: dict[str, Any] = {
        "status": "none",
        "expires_at": 0,
        "dataset_scope": [],
        "purpose": "",
    }
    manifest_denial_reason: str | None = None
    target_job_uuid: uuid.UUID | None = None
    if body.job_id:
        cleaned_job_id = body.job_id.strip()
        try:
            target_job_uuid = uuid.UUID(cleaned_job_id)
        except (ValueError, AttributeError):
            target_job_uuid = None

        if target_job_uuid:
            job_query = select(CASMLJob).where(CASMLJob.id == target_job_uuid)
        else:
            job_query = select(CASMLJob).where(CASMLJob.purpose.ilike(f"%{cleaned_job_id}%"))

        if current_user.role != "admin":
            job_query = job_query.where(CASMLJob.requester_id == current_user.id)

        job_result = await db.execute(job_query)
        job = job_result.scalars().first()
        if job:
            target_job_uuid = job.id
            try:
                if not job.signed_manifest:
                    raise ManifestVerificationError("Approved job has no signed manifest")
                manifest = verify_signed_manifest(
                    job.signed_manifest,
                    settings.manifest_signing_key_bytes,
                )
                if (
                    manifest["job_id"] != str(job.id)
                    or manifest["requester_id"] != str(current_user.id)
                    or manifest["allowed_view"] != job.requested_view
                    or manifest["allowed_view"] != body.requested_view
                    or str(envelope.id) not in manifest["envelope_ids"]
                ):
                    raise ManifestVerificationError("Manifest does not authorize this envelope")
                try:
                    protected_scope = json.loads(job.dataset_scope)
                except json.JSONDecodeError:
                    # Compatibility for pre-002 rows. New job requests are
                    # always persisted as protected scope tokens.
                    protected_scope = [
                        encode_scope_token(
                            compute_hmac_token(item.strip(), settings.index_hmac_key_bytes)
                        )
                        for item in job.dataset_scope.split(",")
                    ]
                job_expires = (
                    job.expires_at if job.expires_at.tzinfo else job.expires_at.replace(tzinfo=UTC)
                )
                job_context = {
                    "id": str(job.id),
                    "status": job.status,
                    "purpose": job.purpose,
                    "expires_at": int(job_expires.timestamp() * 1_000_000_000),
                    "dataset_scope": protected_scope,
                }
            except ManifestVerificationError:
                # Treat an altered, stale, or incomplete manifest exactly like
                # an unapproved job. Do not disclose its contents to callers.
                manifest_denial_reason = "Job manifest does not authorize this access"

    if (
        manifest_denial_reason
        and current_user.role not in ("admin", "trainer")
        and body.requested_view not in ("metadata_only", "masked_image", "raw_image")
    ):
        await append_audit_event(
            db=db,
            event_type="access_deny",
            actor_id=current_user.id,
            actor_role=current_user.role,
            envelope_id=envelope.id,
            decision="deny",
            reason=manifest_denial_reason,
            job_id=target_job_uuid,
        )
        await db.commit()
        raise HTTPException(status_code=403, detail=manifest_denial_reason)

    # 3. Build OPA input (no secrets, no keys, no raw data)
    identity = {
        "user_id": str(current_user.id),
        "role": current_user.role,
    }
    resource = {
        "envelope_id": str(envelope.id),
        "sensitivity": envelope.sensitivity_label,
        "dataset_scope_token": envelope.dataset_scope_token
        or (
            encode_scope_token(
                compute_hmac_token(envelope.dataset_id, settings.index_hmac_key_bytes)
            )
            if envelope.dataset_id
            else ""
        ),
        "uploaded_by": str(envelope.uploaded_by) if envelope.uploaded_by else "",
    }
    context = {
        "purpose": body.purpose,
        "requested_view": body.requested_view,
        "job": job_context,
        "policy_version": None,
    }

    # 4. Evaluate policy -- OPA unavailability -> deny (handled in opa_client)
    decision = await evaluate_access_policy(identity, resource, context)

    if decision.decision == "deny" or not decision.allowed_view:
        await append_audit_event(
            db=db,
            event_type="access_deny",
            actor_id=current_user.id,
            actor_role=current_user.role,
            envelope_id=envelope.id,
            decision="deny",
            reason=decision.reason,
            job_id=target_job_uuid,
        )
        await db.commit()
        raise HTTPException(
            status_code=403,
            detail=decision.reason or "Access denied by policy",
        )

    # 5. Decrypt and minimize data
    try:
        plaintext = retrieve_and_decrypt(envelope, key_service, storage)
    except Exception as exc:
        await append_audit_event(
            db=db,
            event_type="access_deny",
            actor_id=current_user.id,
            actor_role=current_user.role,
            envelope_id=envelope.id,
            decision="deny",
            reason="Decryption integrity check failed",
            job_id=target_job_uuid,
        )
        await db.commit()
        raise HTTPException(
            status_code=500,
            detail="Data decryption failed -- cryptographic integrity check failed",
        ) from exc

    minimized = minimize_data(plaintext, decision.allowed_view)
    data_b64 = base64.b64encode(minimized).decode("ascii") if minimized else None

    # Audit access grant
    await append_audit_event(
        db=db,
        event_type="access_allow",
        actor_id=current_user.id,
        actor_role=current_user.role,
        envelope_id=envelope.id,
        decision="allow",
        reason=decision.reason,
        job_id=target_job_uuid,
        extra={"allowed_view": decision.allowed_view},
    )
    await db.commit()

    return AccessResponse(
        decision=decision.decision,
        reason=decision.reason,
        allowed_view=decision.allowed_view,
        data_b64=data_b64,
        policy_id=decision.policy_id,
        policy_version=decision.policy_version,
    )
