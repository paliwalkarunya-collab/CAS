"""
CAS-SE Celery Worker Application -- Phase 5

Async background tasks:
  - Feature extraction from approved job manifests (ResNet/simple CNN embeddings)
  - Model training (Fashion-MNIST / CIFAR-10 classifiers)
  - Anomaly detection (IsolationForest over audit features) -- Phase 7

Workers consume ONLY the envelopes listed in the signed job manifest.
Every per-record access is audited.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from celery import Celery
from sqlalchemy import select

from app.adapters.factory import build_key_service, build_storage_adapter
from app.core.config import get_settings
from app.db.session import async_session_factory
from app.models.models import CASDataEnvelope, CASMLJob
from app.services.audit import append_audit_event
from app.workers.feature_extractor import process_manifest_envelopes

settings = get_settings()
logger = logging.getLogger("cas_se.worker")

celery_app = Celery(
    "cas_se_worker",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)


@celery_app.task(bind=True, name="cas_se.extract_features")  # type: ignore[untyped-decorator]
def extract_features(self: Any, job_id: str) -> dict[str, Any]:
    """
    Extract feature vectors from the server-persisted approved job manifest.

    Consumes only the envelope_ids listed in the signed manifest.
    Only processes envelopes with allowed_view = 'feature_only'.

    The broker receives only ``job_id``. It never receives a caller-provided
    manifest, encrypted payload, DEK, or KEK. The worker verifies the stored
    manifest HMAC before reading a single envelope.
    """
    logger.info("Starting feature extraction for job %s", job_id)

    async def _run() -> dict[str, Any]:
        try:
            job_uuid = uuid.UUID(job_id)
        except ValueError:
            return {"status": "failed", "reason": "Invalid job identifier"}

        async with async_session_factory() as session:
            job_result = await session.execute(select(CASMLJob).where(CASMLJob.id == job_uuid))
            job = job_result.scalar_one_or_none()
            if job is None or job.status != "approved" or not job.signed_manifest:
                return {"status": "denied", "reason": "No active approved job manifest"}

            try:
                from app.services.manifest import verify_signed_manifest

                manifest = verify_signed_manifest(
                    job.signed_manifest,
                    settings.manifest_signing_key_bytes,
                )
                if manifest["job_id"] != job_id:
                    return {"status": "denied", "reason": "Job manifest is invalid"}
                envelope_ids = [uuid.UUID(value) for value in manifest["envelope_ids"]]
                envelopes_result = await session.execute(
                    select(CASDataEnvelope).where(CASDataEnvelope.id.in_(envelope_ids))
                )
                envelopes = {str(envelope.id): envelope for envelope in envelopes_result.scalars()}
                result = process_manifest_envelopes(
                    job.signed_manifest,
                    envelopes,
                    build_key_service(settings),
                    build_storage_adapter(settings),
                    settings.manifest_signing_key_bytes,
                )
            except Exception:
                # Preserve fail-closed behaviour and do not return storage,
                # signature, or cryptographic implementation details through
                # the broker result backend.
                await append_audit_event(
                    db=session,
                    event_type="access_deny",
                    actor_id=job.requester_id,
                    actor_role="worker",
                    job_id=job.id,
                    decision="deny",
                    reason="Feature extraction authorization or processing failed",
                )
                await session.commit()
                logger.error("Feature extraction failed for job %s", job_id)
                return {"status": "failed", "reason": "Feature extraction failed"}

            for audit_event in result["audit_events"]:
                await append_audit_event(
                    db=session,
                    event_type=audit_event["event_type"],
                    actor_id=job.requester_id,
                    actor_role="worker",
                    envelope_id=uuid.UUID(audit_event["envelope_id"]),
                    job_id=job.id,
                    decision=audit_event["decision"],
                    reason=audit_event["reason"],
                )
            await session.commit()
            return {
                "job_id": job_id,
                "status": "completed",
                "processed": result["processed_count"],
            }

    result = asyncio.run(_run())
    logger.info("Feature extraction complete for job %s: %s", job_id, result["status"])
    return result


@celery_app.task(bind=True, name="cas_se.train_model")  # type: ignore[untyped-decorator]
def train_model(
    self: Any, job_id: str, dataset: str, model_config: dict[str, Any] | None = None
) -> dict[str, Any]:
    """
    Train a classifier on approved feature vectors.

    Dataset must be Fashion-MNIST or CIFAR-10 (public synthetic datasets only).
    Produces accuracy/F1 metrics for the privacy-utility evaluation.
    """
    logger.info("Starting model training for job %s on dataset %s", job_id, dataset)

    if dataset not in ("fashion_mnist", "cifar10"):
        return {"error": f"Unsupported dataset: {dataset}. Use fashion_mnist or cifar10."}

    from app.workers.model_trainer import train_classifier

    metrics = train_classifier(dataset_name=dataset)
    return {
        "job_id": job_id,
        "dataset": dataset,
        "status": "training_complete",
        "metrics": metrics,
    }


@celery_app.task(bind=True, name="cas_se.run_anomaly_detection")  # type: ignore[untyped-decorator]
def run_anomaly_detection(self: Any, lookback_hours: int = 72) -> dict[str, Any]:
    """
    Run IsolationForest anomaly detection over recent audit events.

    Detects:
      - Unusual access volume
      - Denied-request spikes
      - Raw-data request spikes
      - Unusual access times
      - Job failure spikes
      - Excessive dataset diversity

    Anomaly detection is advisory -- it NEVER grants or revokes access.
    """
    from app.workers.anomaly_detector import run_anomaly_detection_scan

    logger.info("Running audit anomaly detection scan (lookback=%dh)", lookback_hours)

    async def _run() -> int:
        async with async_session_factory() as session:
            alerts = await run_anomaly_detection_scan(session, lookback_hours=lookback_hours)
            await session.commit()
            return len(alerts)

    try:
        count = asyncio.run(_run())
        return {
            "status": "completed",
            "alerts_generated": count,
        }
    except Exception:
        logger.error("Anomaly detection failed")
        return {"status": "failed", "error": "Anomaly detection failed"}
