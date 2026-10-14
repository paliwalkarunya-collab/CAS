from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db

router = APIRouter()

# Schemas (centralised in app.schemas per PRD §10.3)
from app.schemas.health import HealthResponse  # noqa: E402


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """
    Service health check.

    Returns the running status of CAS-SE middleware.
    Used by Docker healthchecks, load balancers, and monitoring systems.
    Does NOT expose internal configuration, secrets, or adapter details.
    """
    from app.core.config import get_settings

    s = get_settings()
    return HealthResponse(status="ok", service=s.app_name, version=s.app_version)


@router.get("/metrics")
async def metrics(
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    Operational metrics endpoint (Phase 7).
    Returns real-time architecture telemetry without exposing secrets or keys.
    """
    from app.core.config import get_settings

    settings = get_settings()

    try:
        from sqlalchemy import func, select

        from app.models.models import (
            CASAccessAudit,
            CASAnomalyAlert,
            CASDataEnvelope,
            CASMLJob,
        )

        total_envelopes = (
            await db.execute(select(func.count(CASDataEnvelope.id)))
        ).scalar_one() or 0
        total_audit_events = (
            await db.execute(select(func.count(CASAccessAudit.id)))
        ).scalar_one() or 0
        total_anomalies = (
            await db.execute(select(func.count(CASAnomalyAlert.id)))
        ).scalar_one() or 0
        active_jobs = (
            await db.execute(
                select(func.count(CASMLJob.id)).where(
                    CASMLJob.status.in_(["approved", "in_progress"])
                )
            )
        ).scalar_one() or 0
        denied_requests = (
            await db.execute(
                select(func.count(CASAccessAudit.id)).where(CASAccessAudit.decision == "deny")
            )
        ).scalar_one() or 0

        return {
            "status": "ok",
            "telemetry": {
                "total_envelopes": total_envelopes,
                "total_audit_events": total_audit_events,
                "total_anomalies": total_anomalies,
                "active_ml_jobs": active_jobs,
                "unauthorized_requests_denied": denied_requests,
                "kek_current_version": settings.cas_kek_current_version,
                "storage_adapter": settings.storage_adapter,
                "key_adapter": settings.key_service_adapter,
            },
        }
    except Exception as exc:
        return {
            "status": "ok",
            "telemetry": {
                "total_envelopes": 0,
                "total_audit_events": 0,
                "total_anomalies": 0,
                "active_ml_jobs": 0,
                "unauthorized_requests_denied": 0,
                "kek_current_version": settings.cas_kek_current_version,
                "storage_adapter": settings.storage_adapter,
                "key_adapter": settings.key_service_adapter,
                "database_status": f"disconnected ({type(exc).__name__})",
            },
        }
