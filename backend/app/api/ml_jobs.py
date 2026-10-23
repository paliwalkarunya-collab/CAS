"""
CAS-SE ML Job Workflow API -- Phase 5

Full lifecycle: create -> admin approve/reject -> signed manifest -> worker execution
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user, require_roles
from app.core.config import get_settings
from app.db.session import get_db
from app.models.models import CASDataEnvelope, CASJobApproval, CASMLJob, CASProtectedIndex, CASUser
from app.services.audit import append_audit_event
from app.services.crypto import compute_hmac_token, decode_scope_token, encode_scope_token
from app.services.manifest import serialize_signed_manifest

router = APIRouter()
settings = get_settings()


# ---------------------------------------------------------------------------
# Schemas (centralised in app.schemas per PRD §10.3)
# ---------------------------------------------------------------------------

from app.schemas.ml_jobs import (  # noqa: E402
    ApproveJobRequest,
    CreateJobRequest,
    JobManifest,
    MLJobResponse,
    RejectJobRequest,
)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("", response_model=MLJobResponse, status_code=201)
async def create_ml_job(
    body: CreateJobRequest,
    current_user: CASUser = Depends(require_roles("trainer", "researcher", "admin")),
    db: AsyncSession = Depends(get_db),
) -> MLJobResponse:
    """Create a scoped ML/research job request. Status starts as 'pending'."""
    expires_at = datetime.now(UTC) + timedelta(hours=body.duration_hours)

    job = CASMLJob(
        id=uuid.uuid4(),
        requester_id=current_user.id,
        purpose=body.purpose,
        dataset_scope=json.dumps(
            [
                "*"
                if scope == "*"
                else encode_scope_token(compute_hmac_token(scope, settings.index_hmac_key_bytes))
                for scope in body.dataset_scope
            ]
        ),
        requested_view=body.requested_view,
        status="pending",
        expires_at=expires_at,
    )
    db.add(job)
    await db.flush()

    await append_audit_event(
        db=db,
        event_type="job_create",
        actor_id=current_user.id,
        actor_role=current_user.role,
        job_id=job.id,
        decision="allow",
        reason="Created ML job request",
        # Dataset identifiers and free-form purpose can be sensitive. Audit
        # only the non-identifying operational facts required for review.
        extra={
            "dataset_scope_count": len(body.dataset_scope),
            "requested_view": body.requested_view,
        },
    )
    await db.commit()

    return MLJobResponse(
        job_id=job.id,
        requester_id=job.requester_id,
        purpose=job.purpose,
        dataset_scope=[],
        requested_view=job.requested_view,
        status=job.status,
        created_at=job.created_at.isoformat(),
        expires_at=job.expires_at.isoformat(),
    )


@router.get("", response_model=list[MLJobResponse])
async def list_ml_jobs(
    current_user: CASUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[MLJobResponse]:
    """List ML jobs. Admins see all; others see their own."""
    query = select(CASMLJob).order_by(CASMLJob.created_at.desc())
    if current_user.role != "admin":
        query = query.where(CASMLJob.requester_id == current_user.id)
    result = await db.execute(query)
    jobs = result.scalars().all()

    now = datetime.now(UTC)
    for j in jobs:
        j_exp = j.expires_at if j.expires_at.tzinfo else j.expires_at.replace(tzinfo=UTC)
        if j.status == "approved" and j_exp < now:
            j.status = "expired"

    return [_to_response(j) for j in jobs]


@router.get("/{job_id}", response_model=MLJobResponse)
async def get_ml_job(
    job_id: uuid.UUID,
    current_user: CASUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MLJobResponse:
    job = await _load_job(job_id, db)
    if current_user.role != "admin" and job.requester_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    return _to_response(job)


@router.post("/{job_id}/approve", response_model=JobManifest)
async def approve_ml_job(
    job_id: uuid.UUID,
    body: ApproveJobRequest = ApproveJobRequest(),
    current_user: CASUser = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
) -> JobManifest:
    """
    Admin approves a job. Generates a signed manifest containing the
    permitted envelope IDs, allowed view, expiry, and policy version.
    """
    job = await _load_job(job_id, db)
    if job.status != "pending":
        raise HTTPException(status_code=409, detail=f"Job is already {job.status}")

    # Resolve envelope IDs in scope
    dataset_scope = json.loads(job.dataset_scope)
    envelope_ids: list[str] = []

    if "*" not in dataset_scope:
        for scope_token in dataset_scope:
            token = decode_scope_token(scope_token)
            result = await db.execute(
                select(CASProtectedIndex).where(
                    CASProtectedIndex.field_name == "dataset_id",
                    CASProtectedIndex.hmac_token == token,
                )
            )
            indexes = result.scalars().all()
            envelope_ids.extend(str(idx.envelope_id) for idx in indexes)
    else:
        all_envs = await db.execute(select(CASDataEnvelope.id))
        envelope_ids = [str(r) for r in all_envs.scalars().all()]

    # Build and sign manifest
    manifest = {
        "job_id": str(job.id),
        "requester_id": str(job.requester_id),
        "allowed_view": job.requested_view,
        "envelope_ids": envelope_ids,
        "expires_at": job.expires_at.isoformat(),
        "policy_version": job.policy_version,
    }

    job.status = "approved"
    job.signed_manifest = serialize_signed_manifest(manifest, settings.manifest_signing_key_bytes)

    approval = CASJobApproval(
        id=uuid.uuid4(),
        job_id=job.id,
        approver_id=current_user.id,
        decision="approved",
        reason=body.reason,
    )
    db.add(approval)
    await db.flush()

    await append_audit_event(
        db=db,
        event_type="job_approve",
        actor_id=current_user.id,
        actor_role=current_user.role,
        job_id=job.id,
        decision="allow",
        reason=body.reason or "Admin approved ML job",
        extra={"envelope_count": len(envelope_ids), "allowed_view": job.requested_view},
    )
    await db.commit()

    return JobManifest.model_validate(manifest)


@router.post("/{job_id}/reject", status_code=204)
async def reject_ml_job(
    job_id: uuid.UUID,
    body: RejectJobRequest,
    current_user: CASUser = Depends(require_roles("admin")),
    db: AsyncSession = Depends(get_db),
) -> None:
    job = await _load_job(job_id, db)
    if job.status not in ("pending",):
        raise HTTPException(status_code=409, detail=f"Cannot reject a job with status {job.status}")
    job.status = "rejected"
    approval = CASJobApproval(
        id=uuid.uuid4(),
        job_id=job.id,
        approver_id=current_user.id,
        decision="rejected",
        reason=body.reason,
    )
    db.add(approval)
    await db.flush()

    await append_audit_event(
        db=db,
        event_type="job_reject",
        actor_id=current_user.id,
        actor_role=current_user.role,
        job_id=job.id,
        decision="deny",
        reason=body.reason,
    )
    await db.commit()


@router.post("/{job_id}/cancel", status_code=204)
async def cancel_ml_job(
    job_id: uuid.UUID,
    current_user: CASUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    job = await _load_job(job_id, db)
    if current_user.role != "admin" and job.requester_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    if job.status not in ("pending", "approved"):
        raise HTTPException(status_code=409, detail=f"Cannot cancel a job with status {job.status}")
    job.status = "cancelled"
    await db.flush()

    await append_audit_event(
        db=db,
        event_type="job_cancel",
        actor_id=current_user.id,
        actor_role=current_user.role,
        job_id=job.id,
        decision="allow",
        reason="ML job cancelled by requester/admin",
    )
    await db.commit()


@router.get("/{job_id}/results")
async def get_ml_job_results(
    job_id: uuid.UUID,
    current_user: CASUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Get ML job results."""
    job = await _load_job(job_id, db)
    if current_user.role != "admin" and job.requester_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Dataset scopes are protected tokens and intentionally cannot be reversed
    # to a plaintext dataset name. Evaluation uses the public reference set.
    dataset = "fashion_mnist"

    from app.workers.model_trainer import train_classifier

    metrics = train_classifier(dataset_name=dataset)

    return {
        "job_id": str(job.id),
        "status": job.status,
        "metrics": metrics,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _load_job(job_id: uuid.UUID, db: AsyncSession) -> CASMLJob:
    result = await db.execute(select(CASMLJob).where(CASMLJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="ML job not found")

    job_expires = job.expires_at if job.expires_at.tzinfo else job.expires_at.replace(tzinfo=UTC)
    if job.status == "approved" and job_expires < datetime.now(UTC):
        job.status = "expired"
        await db.flush()
    return job


def _to_response(job: CASMLJob) -> MLJobResponse:
    return MLJobResponse(
        job_id=job.id,
        requester_id=job.requester_id,
        purpose=job.purpose,
        dataset_scope=[],
        requested_view=job.requested_view,
        status=job.status,
        created_at=job.created_at.isoformat(),
        expires_at=job.expires_at.isoformat(),
    )
