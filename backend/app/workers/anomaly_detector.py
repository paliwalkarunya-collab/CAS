"""
CAS-SE Anomaly Detection Worker -- Phase 7

Unsupervised anomaly detection over audit features using IsolationForest.

Features extracted per actor:
  1. Access volume (event count in window)
  2. Denied request count and deny ratio
  3. Raw-data request count (views/decryptions)
  4. Off-hours activity ratio (outside 06:00 - 20:00 UTC)
  5. Dataset diversity (unique envelopes accessed)
  6. Job failures (rejections and cancellations)

Alert types:
  - unusual_access_volume
  - denied_request_spike
  - raw_data_requests
  - unusual_access_time
  - job_failure_spike
  - excessive_dataset_diversity

Invariants:
  - Anomaly detection is purely ADVISORY -- it never grants or revokes access automatically.
  - Never logs secrets, keys, or raw data.
  - Generates audit events for all detected anomaly alerts.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import CASAccessAudit, CASAnomalyAlert
from app.services.audit import append_audit_event

logger = logging.getLogger("cas_se.worker.anomaly_detector")

ALERT_TYPES = {
    "unusual_access_volume",
    "denied_request_spike",
    "raw_data_requests",
    "unusual_access_time",
    "job_failure_spike",
    "excessive_dataset_diversity",
}


def extract_actor_features(
    events: list[CASAccessAudit],
) -> tuple[list[uuid.UUID | None], list[dict[str, Any]], np.ndarray]:
    """
    Extract behavioral summary features per actor from a list of audit events.

    Returns:
      (actor_ids, profile_dicts, feature_matrix)
    """
    actor_events: dict[uuid.UUID | None, list[CASAccessAudit]] = defaultdict(list)
    for event in events:
        actor_events[event.actor_id].append(event)

    actor_ids: list[uuid.UUID | None] = []
    profiles: list[dict[str, Any]] = []
    feature_rows: list[list[float]] = []

    for actor_id, a_events in actor_events.items():
        volume = len(a_events)
        denied_count = 0
        raw_requests = 0
        off_hours_count = 0
        unique_envelopes: set[uuid.UUID] = set()
        job_failures = 0

        for ev in a_events:
            if ev.decision == "deny" or ev.event_type == "access_deny":
                denied_count += 1

            if ev.envelope_id:
                unique_envelopes.add(ev.envelope_id)

            if ev.event_type in ("decryption",) or (ev.extra and '"raw"' in ev.extra.lower()):
                raw_requests += 1

            if ev.event_type in ("job_reject", "job_cancel"):
                job_failures += 1

            occ = ev.occurred_at
            hour = occ.hour if occ else 12
            if hour < 6 or hour >= 20:
                off_hours_count += 1

        deny_ratio = denied_count / max(volume, 1)
        off_hours_ratio = off_hours_count / max(volume, 1)
        diversity_count = len(unique_envelopes)

        profile = {
            "actor_id": actor_id,
            "volume": volume,
            "denied_count": denied_count,
            "deny_ratio": deny_ratio,
            "raw_requests": raw_requests,
            "off_hours_count": off_hours_count,
            "off_hours_ratio": off_hours_ratio,
            "dataset_diversity": diversity_count,
            "job_failures": job_failures,
        }

        features = [
            float(volume),
            float(denied_count),
            float(deny_ratio),
            float(raw_requests),
            float(off_hours_ratio),
            float(diversity_count),
            float(job_failures),
        ]

        actor_ids.append(actor_id)
        profiles.append(profile)
        feature_rows.append(features)

    X = (
        np.array(feature_rows, dtype=np.float32)
        if feature_rows
        else np.empty((0, 7), dtype=np.float32)
    )
    return actor_ids, profiles, X


def detect_anomalies_from_events(
    events: list[CASAccessAudit],
    contamination: float = 0.15,
    random_state: int = 42,
) -> list[dict[str, Any]]:
    """
    Apply IsolationForest + heuristic safeguards to detect suspicious behavior patterns.

    Returns a list of candidate alert dictionaries.
    """
    if not events:
        return []

    _actor_ids, profiles, X = extract_actor_features(events)
    if not profiles:
        return []

    alerts: list[dict[str, Any]] = []

    # 1. IsolationForest scoring when sufficient profiles exist (>= 4)
    iso_anomalies: set[int] = set()
    iso_scores: dict[int, float] = {}

    if len(profiles) >= 4:
        try:
            clf = IsolationForest(
                contamination=contamination,
                random_state=random_state,
                n_estimators=50,
            )
            preds = clf.fit_predict(X)
            decision_scores = clf.decision_function(X)

            for i, (pred, score) in enumerate(zip(preds, decision_scores, strict=True)):
                # In sklearn, -1 is anomaly; decision_function is negative for anomalies
                anomaly_score = float(max(0.0, -score))
                iso_scores[i] = anomaly_score
                if pred == -1:
                    iso_anomalies.add(i)
        except Exception as exc:
            logger.warning("IsolationForest failed, falling back to heuristics: %s", exc)

    # 2. Heuristic evaluation + IsolationForest classification
    for i, prof in enumerate(profiles):
        actor_id = prof["actor_id"]
        is_anomaly = i in iso_anomalies
        anomaly_score = iso_scores.get(i, 0.5)

        detected_types: list[tuple[str, str, float]] = []

        # Check deny spikes
        if prof["denied_count"] >= 3 or prof["deny_ratio"] >= 0.5:
            score = max(anomaly_score, 0.85)
            desc = (
                f"Actor had {prof['denied_count']} denied requests "
                f"({prof['deny_ratio']:.1%} denial rate) out of {prof['volume']} total events."
            )
            detected_types.append(("denied_request_spike", desc, score))

        # Check raw data requests
        if prof["raw_requests"] >= 3:
            score = max(anomaly_score, 0.80)
            desc = f"Actor requested raw data / decryption {prof['raw_requests']} times."
            detected_types.append(("raw_data_requests", desc, score))

        # Check off-hours access
        if prof["off_hours_count"] >= 3 and prof["off_hours_ratio"] >= 0.5:
            score = max(anomaly_score, 0.75)
            desc = (
                f"Actor performed {prof['off_hours_count']} operations outside normal hours "
                f"({prof['off_hours_ratio']:.1%} of their activity)."
            )
            detected_types.append(("unusual_access_time", desc, score))

        # Check excessive dataset diversity
        if prof["dataset_diversity"] >= 15:
            score = max(anomaly_score, 0.78)
            desc = (
                f"Actor touched {prof['dataset_diversity']} distinct encrypted envelopes, "
                "suggesting potential scraping or bulk exfiltration."
            )
            detected_types.append(("excessive_dataset_diversity", desc, score))

        # Check job failure spike
        if prof["job_failures"] >= 2:
            score = max(anomaly_score, 0.70)
            desc = f"Actor encountered {prof['job_failures']} rejected or cancelled ML jobs."
            detected_types.append(("job_failure_spike", desc, score))

        # Check general volume spike if IsolationForest flagged it
        if is_anomaly and not detected_types:
            score = max(anomaly_score, 0.72)
            desc = (
                f"Unusual statistical access pattern detected by IsolationForest "
                f"(volume={prof['volume']}, diversity={prof['dataset_diversity']})."
            )
            detected_types.append(("unusual_access_volume", desc, score))

        # Add top alert for this actor
        for alert_type, desc, score in detected_types:
            alerts.append(
                {
                    "actor_id": actor_id,
                    "alert_type": alert_type,
                    "anomaly_score": score,
                    "description": desc,
                }
            )

    return alerts


async def run_anomaly_detection_scan(
    db: AsyncSession,
    lookback_hours: int = 72,
) -> list[CASAnomalyAlert]:
    """
    Run anomaly detection on recent audit records and persist alerts in cas_anomaly_alerts.
    Also appends an advisory 'anomaly_alert' event to the audit trail.
    """
    cutoff = datetime.now(UTC) - timedelta(hours=lookback_hours)

    res = await db.execute(
        select(CASAccessAudit)
        .where(CASAccessAudit.occurred_at >= cutoff)
        .order_by(CASAccessAudit.occurred_at.asc())
    )
    events = list(res.scalars().all())

    candidate_alerts = detect_anomalies_from_events(events)
    if not candidate_alerts:
        return []

    created_alerts: list[CASAnomalyAlert] = []

    for cand in candidate_alerts:
        actor_id = cand["actor_id"]
        alert_type = cand["alert_type"]

        # Check if an unreviewed alert of the same type was already filed in the last 24h
        recent_cutoff = datetime.now(UTC) - timedelta(hours=24)
        existing = await db.execute(
            select(CASAnomalyAlert)
            .where(
                CASAnomalyAlert.actor_id == actor_id,
                CASAnomalyAlert.alert_type == alert_type,
                CASAnomalyAlert.is_reviewed.is_(False),
                CASAnomalyAlert.detected_at >= recent_cutoff,
            )
            .limit(1)
        )
        if existing.scalar_one_or_none() is not None:
            continue

        alert = CASAnomalyAlert(
            id=uuid.uuid4(),
            alert_type=alert_type,
            actor_id=actor_id,
            anomaly_score=cand["anomaly_score"],
            description=cand["description"],
            is_reviewed=False,
            detected_at=datetime.now(UTC),
        )
        db.add(alert)
        created_alerts.append(alert)

        # Audit the anomaly alert
        await append_audit_event(
            db=db,
            event_type="anomaly_alert",
            actor_id=actor_id,
            decision="alert",
            reason=cand["description"],
            extra={
                "alert_type": alert_type,
                "anomaly_score": cand["anomaly_score"],
            },
        )

    await db.flush()
    return created_alerts
