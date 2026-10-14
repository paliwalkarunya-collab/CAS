"""
Tests for CAS-SE Phase 7: ML Evaluation, Baseline Classifiers, and Anomaly Detection.

Covers:
  - Feature extraction from audit events
  - IsolationForest + heuristic anomaly detection
  - Advisory alerts persistence and audit emission
  - Anomaly duplicate suppression
  - GET /anomalies, POST /anomalies/run, PATCH /anomalies/{id}/review APIs
  - GET /metrics operational telemetry endpoint
  - Baseline classifier benchmarks (Plaintext, Encrypted-RBAC, CAS-SE)
  - Security benchmarks (tampering, AAD swapping, split-key recovery)
  - SVG evaluation chart generation
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from starlette.testclient import TestClient

from app.api.auth import get_current_user
from app.db.session import CASBase, get_db
from app.evaluation.benchmarks import (
    generate_evaluation_charts,
    run_all_benchmarks,
    run_baseline_classifier_comparison,
    run_performance_benchmarks,
    run_security_benchmarks,
)
from app.main import create_app
from app.models.models import CASAccessAudit, CASAnomalyAlert, CASUser
from app.services.audit import append_audit_event
from app.services.identity_service import hash_password
from app.workers.anomaly_detector import (
    detect_anomalies_from_events,
    extract_actor_features,
    run_anomaly_detection_scan,
)

# ---------------------------------------------------------------------------
# Unit Tests: Anomaly Detection Feature Extraction & Heuristics
# ---------------------------------------------------------------------------


def test_actor_feature_extraction() -> None:
    actor_1 = uuid.uuid4()
    actor_2 = uuid.uuid4()
    now = datetime(2026, 10, 13, 12, 0, 0, tzinfo=UTC)  # Business hours
    night = datetime(2026, 10, 13, 2, 0, 0, tzinfo=UTC)  # Off-hours

    events = [
        # Actor 1: normal accesses
        CASAccessAudit(
            id=uuid.uuid4(),
            actor_id=actor_1,
            event_type="access_allow",
            decision="allow",
            occurred_at=now,
            event_hmac="h1",
        ),
        CASAccessAudit(
            id=uuid.uuid4(),
            actor_id=actor_1,
            event_type="upload",
            decision="allow",
            occurred_at=now,
            event_hmac="h2",
        ),
        # Actor 2: denied requests and off-hours activity
        CASAccessAudit(
            id=uuid.uuid4(),
            actor_id=actor_2,
            event_type="access_deny",
            decision="deny",
            occurred_at=night,
            event_hmac="h3",
        ),
        CASAccessAudit(
            id=uuid.uuid4(),
            actor_id=actor_2,
            event_type="access_deny",
            decision="deny",
            occurred_at=night,
            event_hmac="h4",
        ),
    ]

    actor_ids, profiles, X = extract_actor_features(events)
    assert len(actor_ids) == 2
    assert len(profiles) == 2
    assert X.shape == (2, 7)

    prof_map = {p["actor_id"]: p for p in profiles}
    p1 = prof_map[actor_1]
    assert p1["volume"] == 2
    assert p1["denied_count"] == 0
    assert p1["deny_ratio"] == 0.0

    p2 = prof_map[actor_2]
    assert p2["volume"] == 2
    assert p2["denied_count"] == 2
    assert p2["deny_ratio"] == 1.0
    assert p2["off_hours_count"] == 2
    assert p2["off_hours_ratio"] == 1.0


def test_anomaly_detection_heuristics_denied_spike_and_raw_requests() -> None:
    bad_actor = uuid.uuid4()
    now = datetime(2026, 10, 13, 14, 0, 0, tzinfo=UTC)

    # 4 denied requests
    events = [
        CASAccessAudit(
            id=uuid.uuid4(),
            actor_id=bad_actor,
            event_type="access_deny",
            decision="deny",
            occurred_at=now,
            event_hmac=f"hmac_{i}",
        )
        for i in range(4)
    ]
    # 3 raw decryption requests
    events.extend(
        [
            CASAccessAudit(
                id=uuid.uuid4(),
                actor_id=bad_actor,
                event_type="decryption",
                decision="allow",
                extra='{"view_type": "raw"}',
                occurred_at=now,
                event_hmac=f"raw_hmac_{i}",
            )
            for i in range(3)
        ]
    )

    alerts = detect_anomalies_from_events(events)
    assert len(alerts) >= 2
    alert_types = [a["alert_type"] for a in alerts]
    assert "denied_request_spike" in alert_types
    assert "raw_data_requests" in alert_types


def test_anomaly_detection_isolation_forest_volume() -> None:
    now = datetime(2026, 10, 13, 11, 0, 0, tzinfo=UTC)
    events: list[CASAccessAudit] = []

    # 5 baseline actors with 2-3 events each
    for _ in range(5):
        act = uuid.uuid4()
        for _ in range(2):
            events.append(
                CASAccessAudit(
                    id=uuid.uuid4(),
                    actor_id=act,
                    event_type="search",
                    decision="allow",
                    occurred_at=now,
                    event_hmac=str(uuid.uuid4()),
                )
            )

    # 1 anomalous actor with 50 events
    spam_actor = uuid.uuid4()
    for _ in range(50):
        events.append(
            CASAccessAudit(
                id=uuid.uuid4(),
                actor_id=spam_actor,
                event_type="search",
                decision="allow",
                occurred_at=now,
                event_hmac=str(uuid.uuid4()),
            )
        )

    alerts = detect_anomalies_from_events(events, contamination=0.2)
    assert len(alerts) >= 1
    actors_alerted = [a["actor_id"] for a in alerts]
    assert spam_actor in actors_alerted


# ---------------------------------------------------------------------------
# Integration Tests: Anomaly Scan Persistence & Audit Trail
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_anomaly_detection_scan_persists_and_audits() -> None:
    test_db_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(test_db_url, echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.create_all)

    attacker_id = uuid.uuid4()

    async with session_factory() as session:
        # Create 4 denied events for attacker
        for i in range(4):
            await append_audit_event(
                session,
                event_type="access_deny",
                actor_id=attacker_id,
                actor_role="researcher",
                decision="deny",
                reason=f"Denied request {i}",
            )
        await session.commit()

        # Run anomaly detection scan
        alerts = await run_anomaly_detection_scan(session, lookback_hours=24)
        assert len(alerts) >= 1
        assert alerts[0].actor_id == attacker_id
        assert alerts[0].alert_type == "denied_request_spike"
        assert alerts[0].is_reviewed is False

        # Verify anomaly_alert was appended to the audit trail
        audit_res = await session.execute(
            select(CASAccessAudit).where(CASAccessAudit.event_type == "anomaly_alert")
        )
        audit_events = audit_res.scalars().all()
        assert len(audit_events) >= 1
        assert audit_events[0].actor_id == attacker_id

        # Verify duplicate suppression within 24h
        second_scan = await run_anomaly_detection_scan(session, lookback_hours=24)
        assert len(second_scan) == 0

    await engine.dispose()


# ---------------------------------------------------------------------------
# Integration Tests: Phase 7 API Endpoints (Anomalies & Operational Metrics)
# ---------------------------------------------------------------------------


@pytest.fixture
async def phase7_test_context() -> AsyncGenerator[
    tuple[TestClient, async_sessionmaker[AsyncSession], dict[str, CASUser]],
]:
    test_db_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(test_db_url, echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.create_all)

    admin_user = CASUser(
        id=uuid.uuid4(),
        username="admin_p7",
        hashed_password=hash_password("Pass123!"),
        role="admin",
        is_active=True,
    )
    auditor_user = CASUser(
        id=uuid.uuid4(),
        username="auditor_p7",
        hashed_password=hash_password("Pass123!"),
        role="auditor",
        is_active=True,
    )
    uploader_user = CASUser(
        id=uuid.uuid4(),
        username="uploader_p7",
        hashed_password=hash_password("Pass123!"),
        role="uploader",
        is_active=True,
    )

    users_map = {
        "admin": admin_user,
        "auditor": auditor_user,
        "uploader": uploader_user,
    }

    async with session_factory() as session:
        session.add_all(list(users_map.values()))
        await session.commit()

    app = create_app()

    async def override_get_db() -> AsyncGenerator[AsyncSession]:
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    yield client, session_factory, users_map

    app.dependency_overrides.clear()
    await engine.dispose()


@pytest.mark.asyncio
async def test_anomalies_api_endpoints(phase7_test_context) -> None:
    client, session_factory, users = phase7_test_context
    admin = users["admin"]
    auditor = users["auditor"]
    uploader = users["uploader"]
    app = client.app

    suspect_id = uuid.uuid4()

    # Seed an anomaly alert
    alert_id = uuid.uuid4()
    async with session_factory() as session:
        alert = CASAnomalyAlert(
            id=alert_id,
            alert_type="denied_request_spike",
            actor_id=suspect_id,
            anomaly_score=0.92,
            description="High denied request volume detected",
            is_reviewed=False,
            detected_at=datetime.now(UTC),
        )
        session.add(alert)
        await session.commit()

    # 1. Non-auditor/non-admin denied
    app.dependency_overrides[get_current_user] = lambda: uploader
    denied = client.get("/anomalies")
    assert denied.status_code == 403

    # 2. Auditor queries alerts
    app.dependency_overrides[get_current_user] = lambda: auditor
    res = client.get("/anomalies?reviewed=false")
    assert res.status_code == 200
    alerts = res.json()
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "denied_request_spike"
    assert alerts[0]["is_reviewed"] is False

    # 3. Mark alert as reviewed
    patch_res = client.patch(f"/anomalies/{alert_id}/review")
    assert patch_res.status_code == 200
    updated = patch_res.json()
    assert updated["is_reviewed"] is True

    # 4. Trigger on-demand anomaly scan
    app.dependency_overrides[get_current_user] = lambda: admin
    run_res = client.post("/anomalies/run?lookback_hours=48")
    assert run_res.status_code == 200
    assert run_res.json()["status"] == "completed"


@pytest.mark.asyncio
async def test_operational_metrics_endpoint(phase7_test_context) -> None:
    client, _, _ = phase7_test_context

    res = client.get("/metrics")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "telemetry" in data
    telemetry = data["telemetry"]
    assert "total_envelopes" in telemetry
    assert "total_audit_events" in telemetry
    assert "total_anomalies" in telemetry
    assert "kek_current_version" in telemetry


# ---------------------------------------------------------------------------
# Unit Tests: Baseline Classifiers & Benchmarking Framework
# ---------------------------------------------------------------------------


def test_baseline_classifier_comparison() -> None:
    results = run_baseline_classifier_comparison(dataset_name="fashion_mnist", n_samples=100)
    assert len(results) == 3

    archs = [r.architecture for r in results]
    assert "Plaintext" in archs
    assert "Encrypted-RBAC" in archs
    assert "CAS-SE" in archs

    cas_res = next(r for r in results if r.architecture == "CAS-SE")
    assert cas_res.raw_images_released == 0
    assert cas_res.raw_releases_avoided == 100
    assert cas_res.unauthorized_denial_rate == 100.0
    assert cas_res.f1_score >= 0.75  # Verified classification utility


def test_performance_and_security_benchmarks(tmp_path: Path) -> None:
    # Performance benchmarks
    perfs, storage = run_performance_benchmarks(n_iterations=20)
    assert len(perfs) == 3
    assert storage["net_overhead_percentage"] < 5.0  # Storage overhead is sub-5%

    # Security benchmarks
    sec_results = run_security_benchmarks()
    assert len(sec_results) == 4
    for s in sec_results:
        assert s.passed is True

    # Full benchmark report & SVG charts
    report = run_all_benchmarks(dataset_name="cifar10", n_samples=100, n_iterations=10)
    assert report.dataset == "cifar10"
    assert len(report.baseline_comparisons) == 3

    chart_paths = generate_evaluation_charts(report, tmp_path)
    assert len(chart_paths) == 2
    for cp in chart_paths:
        p = Path(cp)
        assert p.exists()
        assert p.stat().st_size > 0
        assert "<svg" in p.read_text(encoding="utf-8")
