"""Tests for CAS-SE Phase 5: ML Jobs Workflow, Manifest Generation, Workers, and Expiration."""

from __future__ import annotations

import base64
import io
import json
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import pytest
from PIL import Image
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from starlette.testclient import TestClient

from app.adapters.storage import LocalFileAdapter
from app.api.auth import get_current_user
from app.core.config import get_settings
from app.db.session import CASBase, get_db
from app.main import create_app
from app.models.models import (
    CASAccessAudit,
    CASDataEnvelope,
    CASMLJob,
    CASProtectedIndex,
    CASUser,
)
from app.services.crypto import (
    build_aad,
    compute_hmac_token,
    encrypt_payload,
    generate_dek,
    wrap_dek,
)
from app.services.identity_service import hash_password
from app.services.manifest import (
    ManifestVerificationError,
    serialize_signed_manifest,
    verify_signed_manifest,
)
from app.workers.feature_extractor import (
    extract_embedding_from_bytes,
    process_manifest_envelopes,
)
from app.workers.model_trainer import train_classifier

settings = get_settings()


def create_patterned_image() -> bytes:
    from PIL import ImageDraw

    img = Image.new("RGB", (64, 64), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.rectangle([10, 10, 40, 40], fill=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def signed_worker_manifest(manifest: dict[str, object]) -> str:
    """Build the same server-side signed document consumed by workers."""
    complete_manifest = {
        "job_id": str(manifest["job_id"]),
        "requester_id": str(manifest.get("requester_id", uuid.uuid4())),
        "allowed_view": str(manifest["allowed_view"]),
        "envelope_ids": manifest["envelope_ids"],
        "expires_at": str(manifest["expires_at"]),
        "policy_version": manifest.get("policy_version"),
    }
    return serialize_signed_manifest(complete_manifest, settings.manifest_signing_key_bytes)


class StaticKeyService:
    """Minimal versioned key service used by worker unit tests."""

    def __init__(self, kek: bytes) -> None:
        self._kek = kek

    def get_current_kek(self) -> tuple[bytes, int]:
        return self._kek, 1

    def get_kek_by_version(self, version: int) -> bytes:
        if version != 1:
            raise KeyError(version)
        return self._kek

    def rotate_kek(self) -> tuple[bytes, int]:
        raise NotImplementedError

    def current_kek_version(self) -> int:
        return 1

    def wrap_dek(self, dek: bytes) -> tuple[str, int]:
        from app.services.crypto import wrap_dek

        wrapped = wrap_dek(dek, self._kek, 1)
        return wrapped.wrapped_dek_b64, 1

    def unwrap_dek(self, wrapped_dek: str, version: int) -> bytes:
        from app.services.crypto import unwrap_dek

        return unwrap_dek(wrapped_dek, self._kek)


# ---------------------------------------------------------------------------
# Unit Tests: Feature Extractor & Model Trainer Workers
# ---------------------------------------------------------------------------


def test_feature_extractor_embedding_shape() -> None:
    img_bytes = create_patterned_image()
    embedding = extract_embedding_from_bytes(img_bytes)
    assert isinstance(embedding, list)
    assert len(embedding) == 64
    assert all(isinstance(x, float) for x in embedding)


def test_model_trainer_fashion_mnist_and_cifar10() -> None:
    res_fmnist = train_classifier("fashion_mnist", random_state=42)
    assert res_fmnist["status"] == "completed"
    assert res_fmnist["dataset"] == "fashion_mnist"
    assert 0.0 <= res_fmnist["accuracy"] <= 1.0
    assert 0.0 <= res_fmnist["f1_score"] <= 1.0
    assert res_fmnist["duration_ms"] > 0

    res_cifar = train_classifier("cifar10", random_state=42)
    assert res_cifar["status"] == "completed"
    assert res_cifar["dataset"] == "cifar10"
    assert 0.0 <= res_cifar["accuracy"] <= 1.0

    with pytest.raises(ValueError, match="Unsupported dataset"):
        train_classifier("invalid_dataset_name")


def test_process_manifest_envelopes_expired_denial() -> None:
    past_expiry = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    manifest = {
        "job_id": str(uuid.uuid4()),
        "allowed_view": "feature_only",
        "envelope_ids": ["env-1"],
        "expires_at": past_expiry,
    }
    with pytest.raises(ValueError, match="expired"):
        process_manifest_envelopes(
            signed_worker_manifest(manifest),
            {},
            StaticKeyService(b"0" * 32),
            None,
            settings.manifest_signing_key_bytes,
        )


def test_process_manifest_envelopes_invalid_view_denial() -> None:
    future_expiry = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    manifest = {
        "job_id": str(uuid.uuid4()),
        "allowed_view": "metadata_only",
        "envelope_ids": ["env-1"],
        "expires_at": future_expiry,
    }
    with pytest.raises(ValueError, match="cannot extract features for view"):
        process_manifest_envelopes(
            signed_worker_manifest(manifest),
            {},
            StaticKeyService(b"0" * 32),
            None,
            settings.manifest_signing_key_bytes,
        )


def test_tampered_signed_manifest_is_rejected_before_worker_processing() -> None:
    future_expiry = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    signed_manifest = signed_worker_manifest(
        {
            "job_id": str(uuid.uuid4()),
            "allowed_view": "feature_only",
            "envelope_ids": ["authorised-envelope"],
            "expires_at": future_expiry,
        }
    )
    tampered = json.loads(signed_manifest)
    tampered["manifest"]["envelope_ids"].append("injected-envelope")

    with pytest.raises(ManifestVerificationError, match="signature is invalid"):
        process_manifest_envelopes(
            json.dumps(tampered),
            {},
            StaticKeyService(b"0" * 32),
            None,
            settings.manifest_signing_key_bytes,
        )


def test_process_manifest_envelopes_execution(tmp_path: pytest.TempPathFactory) -> None:
    storage = LocalFileAdapter(str(tmp_path / "storage"))
    kek = b"k" * 32
    env_id = uuid.uuid4()
    obj_key = f"envelopes/{env_id.hex}"

    raw_img = create_patterned_image()
    dek = generate_dek()
    aad = build_aad(str(env_id), None, "restricted", 1)
    enc = encrypt_payload(raw_img, dek, aad)
    wrapped = wrap_dek(dek, kek, 1)
    storage.put_object(obj_key, enc.ciphertext)

    class DummyEnvelope:
        def __init__(self):
            self.id = env_id
            self.object_uri = obj_key
            self.nonce_hex = enc.nonce.hex()
            self.wrapped_dek = wrapped.wrapped_dek_b64
            self.kek_version = 1
            self.ciphertext_hash = enc.ciphertext_sha256
            self.sensitivity_label = "restricted"
            self.encryption_version = 1
            self.policy_id = None

    envelope_obj = DummyEnvelope()
    future_expiry = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    job_id = str(uuid.uuid4())
    manifest = {
        "job_id": job_id,
        "allowed_view": "feature_only",
        "envelope_ids": [str(env_id)],
        "expires_at": future_expiry,
    }

    result = process_manifest_envelopes(
        signed_worker_manifest(manifest),
        {str(env_id): envelope_obj},
        StaticKeyService(kek),
        storage,
        settings.manifest_signing_key_bytes,
    )
    assert result["processed_count"] == 1
    assert str(env_id) in result["features"]
    assert len(result["features"][str(env_id)]) == 64
    assert len(result["audit_events"]) == 1
    assert result["audit_events"][0]["event_type"] == "decryption"


# ---------------------------------------------------------------------------
# Test Fixture for API Tests
# ---------------------------------------------------------------------------


@pytest.fixture
async def ml_job_test_context(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[tuple[TestClient, async_sessionmaker[AsyncSession], dict[str, CASUser]],]:
    kek_bytes = b"k" * 32
    monkeypatch.setenv("CAS_KEK_V1", base64.b64encode(kek_bytes).decode("ascii"))
    monkeypatch.setenv("CAS_KEK_CURRENT_VERSION", "1")

    test_db_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(test_db_url, echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.create_all)

    admin_user = CASUser(
        id=uuid.uuid4(),
        username="admin_ml",
        hashed_password=hash_password("Pass123!"),
        role="admin",
        is_active=True,
    )
    trainer_user = CASUser(
        id=uuid.uuid4(),
        username="trainer_ml",
        hashed_password=hash_password("Pass123!"),
        role="trainer",
        is_active=True,
    )
    researcher_user = CASUser(
        id=uuid.uuid4(),
        username="researcher_ml",
        hashed_password=hash_password("Pass123!"),
        role="researcher",
        is_active=True,
    )
    other_trainer = CASUser(
        id=uuid.uuid4(),
        username="other_trainer_ml",
        hashed_password=hash_password("Pass123!"),
        role="trainer",
        is_active=True,
    )

    users_map = {
        "admin": admin_user,
        "trainer": trainer_user,
        "researcher": researcher_user,
        "other_trainer": other_trainer,
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


# ---------------------------------------------------------------------------
# Integration Tests: ML Jobs API (POST, GET, Approve, Reject, Cancel, Results)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ml_job_creation_and_listing_scoping(ml_job_test_context) -> None:
    client, session_factory, users = ml_job_test_context
    trainer = users["trainer"]
    other_trainer = users["other_trainer"]
    admin = users["admin"]
    app = client.app

    # 1. Trainer creates job
    app.dependency_overrides[get_current_user] = lambda: trainer
    create_payload = {
        "purpose": "Train baseline ResNet model on Fashion-MNIST dataset",
        "dataset_scope": ["fashion_mnist"],
        "requested_view": "feature_only",
        "duration_hours": 12,
    }
    res = client.post("/ml-jobs", json=create_payload)
    assert res.status_code == 201
    job1_id = res.json()["job_id"]
    assert res.json()["status"] == "pending"

    # 2. Other trainer creates job
    app.dependency_overrides[get_current_user] = lambda: other_trainer
    create_payload2 = {
        "purpose": "Train CIFAR-10 classification benchmark classifier",
        "dataset_scope": ["cifar10"],
        "requested_view": "feature_only",
        "duration_hours": 24,
    }
    res2 = client.post("/ml-jobs", json=create_payload2)
    assert res2.status_code == 201
    job2_id = res2.json()["job_id"]

    # 3. Trainer listing only sees job1
    app.dependency_overrides[get_current_user] = lambda: trainer
    list_res = client.get("/ml-jobs")
    assert list_res.status_code == 200
    trainer_jobs = [j["job_id"] for j in list_res.json()]
    assert job1_id in trainer_jobs
    assert job2_id not in trainer_jobs

    # 4. Admin sees both jobs
    app.dependency_overrides[get_current_user] = lambda: admin
    list_admin = client.get("/ml-jobs")
    assert list_admin.status_code == 200
    admin_jobs = [j["job_id"] for j in list_admin.json()]
    assert job1_id in admin_jobs
    assert job2_id in admin_jobs

    # 5. Verify audit event recorded job_create
    async with session_factory() as session:
        audit_res = await session.execute(
            select(CASAccessAudit).where(
                CASAccessAudit.job_id == uuid.UUID(job1_id),
                CASAccessAudit.event_type == "job_create",
            )
        )
        audit_record = audit_res.scalar_one()
        assert audit_record.actor_id == trainer.id
        assert audit_record.decision == "allow"


@pytest.mark.asyncio
async def test_ml_job_approval_generates_signed_manifest(ml_job_test_context) -> None:
    client, session_factory, users = ml_job_test_context
    trainer = users["trainer"]
    admin = users["admin"]
    app = client.app

    # Seed an envelope with dataset_id = 'fashion_mnist'
    env_id = uuid.uuid4()
    token = compute_hmac_token("fashion_mnist", settings.index_hmac_key_bytes)
    async with session_factory() as session:
        env = CASDataEnvelope(
            id=env_id,
            object_uri=f"envelopes/{env_id.hex}",
            nonce_hex="0" * 24,
            wrapped_dek="wrapped",
            kek_version=1,
            ciphertext_hash="hash",
            sensitivity_label="restricted",
            dataset_id="fashion_mnist",
        )
        idx = CASProtectedIndex(
            id=uuid.uuid4(),
            envelope_id=env_id,
            field_name="dataset_id",
            hmac_token=token,
        )
        session.add_all([env, idx])
        await session.commit()

    # Trainer creates job
    app.dependency_overrides[get_current_user] = lambda: trainer
    res = client.post(
        "/ml-jobs",
        json={
            "purpose": "Train classifier on fashion_mnist",
            "dataset_scope": ["fashion_mnist"],
            "requested_view": "feature_only",
            "duration_hours": 8,
        },
    )
    job_id = res.json()["job_id"]

    # Non-admin cannot approve
    app.dependency_overrides[get_current_user] = lambda: trainer
    denied_res = client.post(f"/ml-jobs/{job_id}/approve", json={"reason": "Self-approve"})
    assert denied_res.status_code == 403

    # Admin approves
    app.dependency_overrides[get_current_user] = lambda: admin
    approve_res = client.post(
        f"/ml-jobs/{job_id}/approve", json={"reason": "Approved for training"}
    )
    assert approve_res.status_code == 200
    manifest = approve_res.json()

    assert manifest["job_id"] == job_id
    assert manifest["allowed_view"] == "feature_only"
    assert str(env_id) in manifest["envelope_ids"]
    assert "manifest_token" not in manifest

    # Verify job status in DB
    async with session_factory() as session:
        job_db = await session.execute(select(CASMLJob).where(CASMLJob.id == uuid.UUID(job_id)))
        job_rec = job_db.scalar_one()
        assert job_rec.status == "approved"
        assert job_rec.signed_manifest is not None
        persisted_manifest = verify_signed_manifest(
            job_rec.signed_manifest,
            settings.manifest_signing_key_bytes,
        )
        assert persisted_manifest["job_id"] == job_id

        # Verify audit event for job_approve
        audit_res = await session.execute(
            select(CASAccessAudit).where(
                CASAccessAudit.job_id == uuid.UUID(job_id),
                CASAccessAudit.event_type == "job_approve",
            )
        )
        audit_rec = audit_res.scalar_one()
        assert audit_rec.actor_id == admin.id
        assert audit_rec.decision == "allow"


@pytest.mark.asyncio
async def test_ml_job_rejection_and_cancellation(ml_job_test_context) -> None:
    client, _session_factory, users = ml_job_test_context
    trainer = users["trainer"]
    admin = users["admin"]
    app = client.app

    # Create job to reject
    app.dependency_overrides[get_current_user] = lambda: trainer
    res1 = client.post(
        "/ml-jobs",
        json={
            "purpose": "Job that will be rejected by policy compliance",
            "dataset_scope": ["unapproved_dataset"],
            "requested_view": "raw_image",
            "duration_hours": 1,
        },
    )
    job_to_reject = res1.json()["job_id"]

    # Admin rejects
    app.dependency_overrides[get_current_user] = lambda: admin
    rej_res = client.post(
        f"/ml-jobs/{job_to_reject}/reject",
        json={"reason": "Raw image view not allowed for trainer"},
    )
    assert rej_res.status_code == 204

    # Create job to cancel
    app.dependency_overrides[get_current_user] = lambda: trainer
    res2 = client.post(
        "/ml-jobs",
        json={
            "purpose": "Job that trainer decides to cancel manually",
            "dataset_scope": ["fashion_mnist"],
            "requested_view": "feature_only",
            "duration_hours": 1,
        },
    )
    job_to_cancel = res2.json()["job_id"]

    # Trainer cancels own job
    cancel_res = client.post(f"/ml-jobs/{job_to_cancel}/cancel")
    assert cancel_res.status_code == 204

    # Verify statuses
    app.dependency_overrides[get_current_user] = lambda: admin
    j1_check = client.get(f"/ml-jobs/{job_to_reject}")
    assert j1_check.json()["status"] == "rejected"

    j2_check = client.get(f"/ml-jobs/{job_to_cancel}")
    assert j2_check.json()["status"] == "cancelled"


@pytest.mark.asyncio
async def test_ml_job_expiration_enforcement(ml_job_test_context) -> None:
    client, session_factory, users = ml_job_test_context
    trainer = users["trainer"]
    app = client.app

    past_time = datetime.now(UTC) - timedelta(hours=2)
    job_id = uuid.uuid4()

    # Manually insert an expired job into the database
    async with session_factory() as session:
        expired_job = CASMLJob(
            id=job_id,
            requester_id=trainer.id,
            purpose="Expired job test verification",
            dataset_scope='["fashion_mnist"]',
            requested_view="feature_only",
            status="approved",  # was approved, but time passed
            expires_at=past_time,
        )
        session.add(expired_job)
        await session.commit()

    # Accessing job should automatically detect and update status to 'expired'
    app.dependency_overrides[get_current_user] = lambda: trainer
    get_res = client.get(f"/ml-jobs/{job_id}")
    assert get_res.status_code == 200
    assert get_res.json()["status"] == "expired"


@pytest.mark.asyncio
async def test_ml_job_results_endpoint(ml_job_test_context) -> None:
    client, _session_factory, users = ml_job_test_context
    trainer = users["trainer"]
    app = client.app

    app.dependency_overrides[get_current_user] = lambda: trainer
    res = client.post(
        "/ml-jobs",
        json={
            "purpose": "Evaluate model utility on fashion_mnist",
            "dataset_scope": ["fashion_mnist"],
            "requested_view": "feature_only",
            "duration_hours": 4,
        },
    )
    job_id = res.json()["job_id"]

    results_res = client.get(f"/ml-jobs/{job_id}/results")
    assert results_res.status_code == 200
    results_data = results_res.json()
    assert results_data["job_id"] == job_id
    assert "metrics" in results_data
    assert results_data["metrics"]["dataset"] == "fashion_mnist"
    assert "accuracy" in results_data["metrics"]
