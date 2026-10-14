"""
CAS-SE Audit API -- Phase 6

GET /audit         -- Filterable audit query (auditor/admin only)
GET /audit/verify  -- Chain integrity verification
GET /anomalies     -- Anomaly alerts (Phase 7)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import require_roles
from app.core.config import get_settings
from app.db.session import get_db
from app.models.models import CASAccessAudit, CASAnomalyAlert
from app.services.audit import verify_chain

router = APIRouter()
settings = get_settings()


# Schemas (centralised in app.schemas per PRD §10.3)
from app.schemas.audit import (  # noqa: E402
    AnomalyAlertResponse,
    AuditEventResponse,
    ChainVerifyResponse,
    CheckpointResponse,
    RunAnomaliesResponse,
)


@router.get("", response_model=list[AuditEventResponse])
async def query_audit(
    actor_id: uuid.UUID | None = Query(None),
    envelope_id: uuid.UUID | None = Query(None),
    event_type: str | None = Query(None),
    decision: str | None = Query(None),
    from_time: datetime | None = Query(None),
    to_time: datetime | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _: object = Depends(require_roles("admin", "auditor")),
    db: AsyncSession = Depends(get_db),
) -> list[AuditEventResponse]:
    """
    Query the audit trail with optional filters.

    Requires admin or auditor role. HMAC values are never returned -- use /verify.
    """
    filters = []
    if actor_id:
        filters.append(CASAccessAudit.actor_id == actor_id)
    if envelope_id:
        filters.append(CASAccessAudit.envelope_id == envelope_id)
    if event_type:
        filters.append(CASAccessAudit.event_type == event_type)
    if decision:
        filters.append(CASAccessAudit.decision == decision)
    if from_time:
        filters.append(CASAccessAudit.occurred_at >= from_time)
    if to_time:
        filters.append(CASAccessAudit.occurred_at <= to_time)

    query = select(CASAccessAudit)
    if filters:
        query = query.where(and_(*filters))
    query = query.order_by(CASAccessAudit.occurred_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    events = result.scalars().all()

    return [
        AuditEventResponse(
            event_id=e.id,
            event_type=e.event_type,
            actor_id=e.actor_id,
            actor_role=e.actor_role,
            envelope_id=e.envelope_id,
            decision=e.decision,
            reason=e.reason,
            job_id=e.job_id,
            occurred_at=e.occurred_at.isoformat(),
        )
        for e in events
    ]


@router.get("/verify", response_model=ChainVerifyResponse)
async def verify_audit_chain(
    _: object = Depends(require_roles("admin", "auditor")),
    db: AsyncSession = Depends(get_db),
) -> ChainVerifyResponse:
    """
    Verify the integrity of the entire audit chain.

    Recomputes HMAC for every event and checks the chain link.
    Returns whether the chain is intact or identifies the first broken link.
    """
    # Count events
    count_result = await db.execute(select(CASAccessAudit.id))
    count = len(count_result.scalars().all())

    is_valid, message = await verify_chain(db)

    # Append an audit_verify event for the verification itself
    # (minimal audit for the verification action -- no circular import issue as we import here)

    return ChainVerifyResponse(
        is_valid=is_valid,
        message=message,
        events_verified=count,
    )


@router.get("/checkpoint", response_model=CheckpointResponse)
async def export_audit_checkpoint(
    _: object = Depends(require_roles("admin", "auditor")),
    db: AsyncSession = Depends(get_db),
) -> CheckpointResponse:
    """
    Export a signed audit checkpoint for verification against external ledgers / WORM storage.
    """
    # Get latest event
    latest_res = await db.execute(
        select(CASAccessAudit).order_by(CASAccessAudit.occurred_at.desc()).limit(1)
    )
    latest_event = latest_res.scalar_one_or_none()

    count_res = await db.execute(select(CASAccessAudit.id))
    total_events = len(count_res.scalars().all())

    now_iso = datetime.now(UTC).isoformat()
    last_id = latest_event.id if latest_event else None
    last_hmac = latest_event.event_hmac if latest_event else None

    checkpoint_data = {
        "last_event_id": str(last_id) if last_id else "",
        "last_event_hmac": last_hmac or "",
        "total_events": total_events,
        "checkpoint_timestamp": now_iso,
    }
    serialized = json.dumps(checkpoint_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(settings.audit_integrity_key_bytes, serialized, hashlib.sha256).hexdigest()

    return CheckpointResponse(
        last_event_id=last_id,
        last_event_hmac=last_hmac,
        total_events=total_events,
        checkpoint_timestamp=now_iso,
        checkpoint_signature=signature,
    )


anomalies_router = APIRouter()


@anomalies_router.get("", response_model=list[AnomalyAlertResponse])
@router.get("/anomalies", response_model=list[AnomalyAlertResponse])
async def list_anomalies(
    reviewed: bool | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    _: object = Depends(require_roles("admin", "auditor")),
    db: AsyncSession = Depends(get_db),
) -> list[AnomalyAlertResponse]:
    """
    List anomaly detection alerts generated by the IsolationForest worker (Phase 7).

    Anomaly detection is advisory -- it never grants or revokes access automatically.
    """
    filters = []
    if reviewed is not None:
        filters.append(CASAnomalyAlert.is_reviewed == reviewed)

    query = select(CASAnomalyAlert)
    if filters:
        query = query.where(and_(*filters))
    query = query.order_by(CASAnomalyAlert.detected_at.desc()).limit(limit)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return [
        AnomalyAlertResponse(
            alert_id=a.id,
            alert_type=a.alert_type,
            actor_id=a.actor_id,
            anomaly_score=a.anomaly_score,
            description=a.description,
            is_reviewed=a.is_reviewed,
            detected_at=a.detected_at.isoformat(),
        )
        for a in alerts
    ]


@anomalies_router.post("/run", response_model=RunAnomaliesResponse)
@router.post("/anomalies/run", response_model=RunAnomaliesResponse)
async def trigger_anomaly_detection(
    lookback_hours: int = Query(72, ge=1, le=720),
    _: object = Depends(require_roles("admin", "auditor")),
    db: AsyncSession = Depends(get_db),
) -> RunAnomaliesResponse:
    """
    Trigger on-demand audit anomaly detection scan.
    """
    from app.workers.anomaly_detector import run_anomaly_detection_scan

    alerts = await run_anomaly_detection_scan(db, lookback_hours=lookback_hours)
    await db.commit()
    return RunAnomaliesResponse(status="completed", alerts_created=len(alerts))


@anomalies_router.patch("/{alert_id}/review", response_model=AnomalyAlertResponse)
@router.patch("/anomalies/{alert_id}/review", response_model=AnomalyAlertResponse)
async def review_anomaly(
    alert_id: uuid.UUID,
    _: object = Depends(require_roles("admin", "auditor")),
    db: AsyncSession = Depends(get_db),
) -> AnomalyAlertResponse:
    """
    Mark an anomaly alert as reviewed by an auditor or admin.
    """
    res = await db.execute(select(CASAnomalyAlert).where(CASAnomalyAlert.id == alert_id))
    alert = res.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Anomaly alert not found")

    alert.is_reviewed = True
    await db.commit()
    await db.refresh(alert)
    return AnomalyAlertResponse(
        alert_id=alert.id,
        alert_type=alert.alert_type,
        actor_id=alert.actor_id,
        anomaly_score=alert.anomaly_score,
        description=alert.description,
        is_reviewed=alert.is_reviewed,
        detected_at=alert.detected_at.isoformat(),
    )
