"""Tests for CAS-SE Phase 4: Policy Engine, Protected Search, Access Control, and Data Minimization."""

from __future__ import annotations

import base64
import io
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from PIL import Image
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from starlette.testclient import TestClient

from app.adapters.key_service import EnvVarKeyService
from app.adapters.storage import LocalFileAdapter
from app.api.auth import get_current_user
from app.api.envelopes import get_key_service, get_storage_adapter
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
from app.policy.opa_client import PolicyDecision, evaluate_access_policy
from app.services.crypto import (
    build_aad,
    compute_hmac_token,
    encrypt_payload,
    generate_dek,
    wrap_dek,
)
from app.services.identity_service import hash_password
from app.services.manifest import serialize_signed_manifest

settings = get_settings()


def create_patterned_image() -> bytes:
    from PIL import ImageDraw

    img = Image.new("RGB", (64, 64), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.rectangle([10, 10, 40, 40], fill=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def signed_job_manifest(
    job_id: uuid.UUID,
    requester_id: uuid.UUID,
    allowed_view: str,
    envelope_ids: list[uuid.UUID],
    expires_at: datetime,
) -> str:
    return serialize_signed_manifest(
        {
            "job_id": str(job_id),
            "requester_id": str(requester_id),
            "allowed_view": allowed_view,
            "envelope_ids": [str(envelope_id) for envelope_id in envelope_ids],
            "expires_at": expires_at.isoformat(),
            "policy_version": None,
        },
        settings.manifest_signing_key_bytes,
    )


# ---------------------------------------------------------------------------
# Unit Tests: OPA Client & Fail-Closed Behavior
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_opa_client_evaluates_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    async def mock_post(self, url, json=None, **kwargs):
        return httpx.Response(
            200,
            json={
                "result": {
                    "allow": True,
                    "decision": "feature_only",
                    "allowed_view": "feature_only",
                    "reason": "Access granted",
                    "policy_id": "pol-1",
                    "policy_version": 1,
                }
            },
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    decision = await evaluate_access_policy(
        identity={"user_id": "u1", "role": "trainer"},
        resource={"envelope_id": "env-1", "sensitivity": "restricted"},
        context={"purpose": "model_training", "requested_view": "feature_only"},
    )
    assert decision.decision == "feature_only"
    assert decision.allowed_view == "feature_only"
    assert decision.reason == "Access granted"


@pytest.mark.asyncio
async def test_opa_client_evaluates_deny(monkeypatch: pytest.MonkeyPatch) -> None:
    async def mock_post(self, url, json=None, **kwargs):
        return httpx.Response(
            200,
            json={
                "result": {
                    "allow": False,
                    "decision": "deny",
                    "reason": "Trainer raw-image access is never permitted",
                }
            },
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    decision = await evaluate_access_policy(
        identity={"user_id": "u1", "role": "trainer"},
        resource={"envelope_id": "env-1", "sensitivity": "restricted"},
        context={"purpose": "model_training", "requested_view": "raw_image"},
    )
    assert decision.decision == "deny"
    assert decision.allowed_view is None
    assert "Trainer raw-image" in decision.reason


@pytest.mark.asyncio
async def test_opa_client_fail_closed_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    async def mock_post(self, url, json=None, **kwargs):
        raise httpx.TimeoutException("Timeout contacting OPA engine")

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    decision = await evaluate_access_policy(
        identity={"user_id": "u1", "role": "admin"},
        resource={"envelope_id": "env-1"},
        context={"requested_view": "metadata_only"},
    )
    assert decision.decision == "deny"
    assert decision.allowed_view is None
    assert "unavailable" in decision.reason or "timeout" in decision.reason.lower()


@pytest.mark.asyncio
async def test_opa_client_fail_closed_on_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    async def mock_post(self, url, json=None, **kwargs):
        return httpx.Response(500, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    decision = await evaluate_access_policy(
        identity={"user_id": "u1", "role": "admin"},
        resource={"envelope_id": "env-1"},
        context={"requested_view": "metadata_only"},
    )
    assert decision.decision == "deny"
    assert decision.allowed_view is None


# ---------------------------------------------------------------------------
# Test Fixture for Database & App Context
# ---------------------------------------------------------------------------


@pytest.fixture
async def access_test_context(
    tmp_path: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[
    tuple[TestClient, async_sessionmaker[AsyncSession], LocalFileAdapter, dict[str, CASUser]],
]:
    # Configure test KEK
    kek_bytes = b"k" * 32
    monkeypatch.setenv("CAS_KEK_V1", base64.b64encode(kek_bytes).decode("ascii"))
    monkeypatch.setenv("CAS_KEK_CURRENT_VERSION", "1")

    # In-memory DB
    test_db_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(test_db_url, echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.create_all)

    # Seed users
    admin_user = CASUser(
        id=uuid.uuid4(),
        username="admin_p4",
        email="admin_p4@test.org",
        hashed_password=hash_password("Pass123!"),
        role="admin",
        is_active=True,
    )
    uploader_user = CASUser(
        id=uuid.uuid4(),
        username="uploader_p4",
        email="uploader_p4@test.org",
        hashed_password=hash_password("Pass123!"),
        role="uploader",
        is_active=True,
    )
    other_uploader = CASUser(
        id=uuid.uuid4(),
        username="other_uploader_p4",
        email="other_uploader_p4@test.org",
        hashed_password=hash_password("Pass123!"),
        role="uploader",
        is_active=True,
    )
    trainer_user = CASUser(
        id=uuid.uuid4(),
        username="trainer_p4",
        email="trainer_p4@test.org",
        hashed_password=hash_password("Pass123!"),
        role="trainer",
        is_active=True,
    )
    researcher_user = CASUser(
        id=uuid.uuid4(),
        username="researcher_p4",
        email="researcher_p4@test.org",
        hashed_password=hash_password("Pass123!"),
        role="researcher",
        is_active=True,
    )
    auditor_user = CASUser(
        id=uuid.uuid4(),
        username="auditor_p4",
        email="auditor_p4@test.org",
        hashed_password=hash_password("Pass123!"),
        role="auditor",
        is_active=True,
    )

    users_map = {
        "admin": admin_user,
        "uploader": uploader_user,
        "other_uploader": other_uploader,
        "trainer": trainer_user,
        "researcher": researcher_user,
        "auditor": auditor_user,
    }

    async with session_factory() as session:
        session.add_all(list(users_map.values()))
        await session.commit()

    storage_adapter = LocalFileAdapter(str(tmp_path / "storage"))
    key_service = EnvVarKeyService()

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
    app.dependency_overrides[get_storage_adapter] = lambda: storage_adapter
    app.dependency_overrides[get_key_service] = lambda: key_service

    client = TestClient(app)

    yield client, session_factory, storage_adapter, users_map

    app.dependency_overrides.clear()
    await engine.dispose()


# ---------------------------------------------------------------------------
# Integration Tests: Protected Search (POST /search)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_protected_search_equality_token_lookup(access_test_context) -> None:
    client, session_factory, storage, users = access_test_context
    uploader = users["uploader"]
    other_uploader = users["other_uploader"]
    admin = users["admin"]
    kek = b"k" * 32

    # Ingest 2 envelopes manually into DB & storage
    env1_id = uuid.uuid4()
    obj1_key = f"envelopes/{env1_id.hex}"
    raw1 = create_patterned_image()
    dek1 = generate_dek()
    aad1 = build_aad(str(env1_id), None, "restricted", 1)
    enc1 = encrypt_payload(raw1, dek1, aad1)
    wrapped1 = wrap_dek(dek1, kek, 1)
    storage.put_object(obj1_key, enc1.ciphertext)

    env2_id = uuid.uuid4()
    obj2_key = f"envelopes/{env2_id.hex}"
    raw2 = create_patterned_image()
    dek2 = generate_dek()
    aad2 = build_aad(str(env2_id), None, "restricted", 1)
    enc2 = encrypt_payload(raw2, dek2, aad2)
    wrapped2 = wrap_dek(dek2, kek, 1)
    storage.put_object(obj2_key, enc2.ciphertext)

    token_chest1 = compute_hmac_token("chest-xray", settings.index_hmac_key_bytes)
    token_covid = compute_hmac_token("covid-19", settings.index_hmac_key_bytes)

    async with session_factory() as session:
        e1 = CASDataEnvelope(
            id=env1_id,
            object_uri=obj1_key,
            nonce_hex=enc1.nonce.hex(),
            wrapped_dek=wrapped1.wrapped_dek_b64,
            kek_version=1,
            ciphertext_hash=enc1.ciphertext_sha256,
            sensitivity_label="restricted",
            dataset_id="chest-xray",
            uploaded_by=uploader.id,
        )
        e2 = CASDataEnvelope(
            id=env2_id,
            object_uri=obj2_key,
            nonce_hex=enc2.nonce.hex(),
            wrapped_dek=wrapped2.wrapped_dek_b64,
            kek_version=1,
            ciphertext_hash=enc2.ciphertext_sha256,
            sensitivity_label="restricted",
            dataset_id="covid-19",
            uploaded_by=other_uploader.id,
        )
        idx1 = CASProtectedIndex(
            id=uuid.uuid4(),
            envelope_id=env1_id,
            field_name="dataset_id",
            hmac_token=token_chest1,
        )
        idx2 = CASProtectedIndex(
            id=uuid.uuid4(),
            envelope_id=env2_id,
            field_name="dataset_id",
            hmac_token=token_covid,
        )
        session.add_all([e1, e2, idx1, idx2])
        await session.commit()

    app = client.app

    # 1. Search as admin for chest-xray
    app.dependency_overrides[get_current_user] = lambda: admin
    res = client.post("/search", json={"field_name": "dataset_id", "value": "chest-xray"})
    assert res.status_code == 200
    results = res.json()
    assert len(results) == 1
    assert results[0]["envelope_id"] == str(env1_id)
    assert "dataset_id" not in results[0]

    # 2. Search as other_uploader for chest-xray -> returns empty list (scoped to own uploads)
    app.dependency_overrides[get_current_user] = lambda: other_uploader
    res_other = client.post("/search", json={"field_name": "dataset_id", "value": "chest-xray"})
    assert res_other.status_code == 200
    assert len(res_other.json()) == 0

    # 3. Search invalid field -> returns 400
    res_invalid = client.post("/search", json={"field_name": "patient_ssn", "value": "secret"})
    assert res_invalid.status_code == 400

    # 4. Verify audit trail has search entries
    async with session_factory() as session:
        audit_res = await session.execute(
            select(CASAccessAudit).where(CASAccessAudit.event_type == "search")
        )
        audit_events = audit_res.scalars().all()
        assert len(audit_events) >= 3


# ---------------------------------------------------------------------------
# Integration Tests: Access Request (POST /access-request)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_access_request_trainer_feature_only_granted(
    access_test_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, session_factory, storage, users = access_test_context
    trainer = users["trainer"]
    kek = b"k" * 32

    # Ingest envelope
    env_id = uuid.uuid4()
    obj_key = f"envelopes/{env_id.hex}"
    raw_img = create_patterned_image()
    dek = generate_dek()
    aad = build_aad(str(env_id), None, "restricted", 1)
    enc = encrypt_payload(raw_img, dek, aad)
    wrapped = wrap_dek(dek, kek, 1)
    storage.put_object(obj_key, enc.ciphertext)

    job_id = uuid.uuid4()
    future_expiry = datetime.now(UTC) + timedelta(hours=2)

    async with session_factory() as session:
        env = CASDataEnvelope(
            id=env_id,
            object_uri=obj_key,
            nonce_hex=enc.nonce.hex(),
            wrapped_dek=wrapped.wrapped_dek_b64,
            kek_version=1,
            ciphertext_hash=enc.ciphertext_sha256,
            sensitivity_label="restricted",
            dataset_id="cifar-10",
        )
        job = CASMLJob(
            id=job_id,
            requester_id=trainer.id,
            status="approved",
            purpose="model_training",
            requested_view="feature_only",
            dataset_scope="cifar-10",
            expires_at=future_expiry,
            signed_manifest=signed_job_manifest(
                job_id,
                trainer.id,
                "feature_only",
                [env_id],
                future_expiry,
            ),
        )
        session.add_all([env, job])
        await session.commit()

    # Mock OPA to return allow feature_only
    async def mock_opa(identity, resource, context):
        return PolicyDecision(
            decision="feature_only",
            reason="Access granted",
            policy_id="pol-1",
            policy_version=1,
            allowed_view="feature_only",
            decision_expiry=None,
        )

    monkeypatch.setattr("app.api.access.evaluate_access_policy", mock_opa)

    app = client.app
    app.dependency_overrides[get_current_user] = lambda: trainer

    res = client.post(
        "/access-request",
        json={
            "envelope_id": str(env_id),
            "purpose": "model_training",
            "requested_view": "feature_only",
            "job_id": str(job_id),
        },
    )
    assert res.status_code == 200
    assert res.json()["decision"] == "feature_only"
    assert res.json()["allowed_view"] == "feature_only"

    # Verify audit event recorded access_allow
    async with session_factory() as session:
        audit_res = await session.execute(
            select(CASAccessAudit).where(
                CASAccessAudit.envelope_id == env_id,
                CASAccessAudit.event_type == "access_allow",
            )
        )
        audit_row = audit_res.scalar_one()
        assert audit_row.actor_id == trainer.id
        assert audit_row.decision == "allow"


@pytest.mark.asyncio
async def test_access_request_trainer_raw_image_denied(
    access_test_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, session_factory, _storage, users = access_test_context
    trainer = users["trainer"]

    env_id = uuid.uuid4()
    async with session_factory() as session:
        env = CASDataEnvelope(
            id=env_id,
            object_uri=f"envelopes/{env_id.hex}",
            nonce_hex="0" * 24,
            wrapped_dek="wrapped",
            kek_version=1,
            ciphertext_hash="hash",
            sensitivity_label="restricted",
        )
        session.add(env)
        await session.commit()

    # Mock OPA returning deny for trainer raw image
    async def mock_opa(identity, resource, context):
        return PolicyDecision(
            decision="deny",
            reason="Trainer raw-image access is never permitted",
            policy_id=None,
            policy_version=None,
            allowed_view=None,
            decision_expiry=None,
        )

    monkeypatch.setattr("app.api.access.evaluate_access_policy", mock_opa)

    app = client.app
    app.dependency_overrides[get_current_user] = lambda: trainer

    res = client.post(
        "/access-request",
        json={
            "envelope_id": str(env_id),
            "purpose": "model_training",
            "requested_view": "raw_image",
        },
    )
    assert res.status_code == 403
    assert "Trainer raw-image" in res.json()["detail"]

    # Verify audit recorded access_deny
    async with session_factory() as session:
        audit_res = await session.execute(
            select(CASAccessAudit).where(
                CASAccessAudit.envelope_id == env_id,
                CASAccessAudit.event_type == "access_deny",
            )
        )
        audit_row = audit_res.scalar_one()
        assert audit_row.actor_id == trainer.id
        assert audit_row.decision == "deny"


@pytest.mark.asyncio
async def test_access_request_researcher_raw_image_granted(
    access_test_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, session_factory, storage, users = access_test_context
    researcher = users["researcher"]
    kek = b"k" * 32

    # Ingest envelope
    env_id = uuid.uuid4()
    obj_key = f"envelopes/{env_id.hex}"
    raw_img = create_patterned_image()
    dek = generate_dek()
    aad = build_aad(str(env_id), None, "restricted", 1)
    enc = encrypt_payload(raw_img, dek, aad)
    wrapped = wrap_dek(dek, kek, 1)
    storage.put_object(obj_key, enc.ciphertext)

    job_id = uuid.uuid4()
    future_expiry = datetime.now(UTC) + timedelta(hours=2)

    async with session_factory() as session:
        env = CASDataEnvelope(
            id=env_id,
            object_uri=obj_key,
            nonce_hex=enc.nonce.hex(),
            wrapped_dek=wrapped.wrapped_dek_b64,
            kek_version=1,
            ciphertext_hash=enc.ciphertext_sha256,
            sensitivity_label="restricted",
            dataset_id="research-cohort-01",
        )
        job = CASMLJob(
            id=job_id,
            requester_id=researcher.id,
            status="approved",
            purpose="research",
            requested_view="raw_image",
            dataset_scope="research-cohort-01",
            expires_at=future_expiry,
            signed_manifest=signed_job_manifest(
                job_id,
                researcher.id,
                "raw_image",
                [env_id],
                future_expiry,
            ),
        )
        session.add_all([env, job])
        await session.commit()

    async def mock_opa(identity, resource, context):
        return PolicyDecision(
            decision="raw_image",
            reason="Access granted",
            policy_id="pol-1",
            policy_version=1,
            allowed_view="raw_image",
            decision_expiry=None,
        )

    monkeypatch.setattr("app.api.access.evaluate_access_policy", mock_opa)

    app = client.app
    app.dependency_overrides[get_current_user] = lambda: researcher

    res = client.post(
        "/access-request",
        json={
            "envelope_id": str(env_id),
            "purpose": "research",
            "requested_view": "raw_image",
            "job_id": str(job_id),
        },
    )
    assert res.status_code == 200
    data_b64 = res.json()["data_b64"]
    assert data_b64 is not None
    # Verify decrypted payload matches original raw image
    assert base64.b64decode(data_b64) == raw_img


@pytest.mark.asyncio
async def test_access_request_expired_job_denied(
    access_test_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, session_factory, _storage, users = access_test_context
    researcher = users["researcher"]

    env_id = uuid.uuid4()
    async with session_factory() as session:
        env = CASDataEnvelope(
            id=env_id,
            object_uri=f"envelopes/{env_id.hex}",
            nonce_hex="0" * 24,
            wrapped_dek="wrapped",
            kek_version=1,
            ciphertext_hash="hash",
            sensitivity_label="restricted",
        )
        session.add(env)
        await session.commit()

    async def mock_opa(identity, resource, context):
        return PolicyDecision(
            decision="deny",
            reason="Job is expired",
            policy_id=None,
            policy_version=None,
            allowed_view=None,
            decision_expiry=None,
        )

    monkeypatch.setattr("app.api.access.evaluate_access_policy", mock_opa)

    app = client.app
    app.dependency_overrides[get_current_user] = lambda: researcher

    res = client.post(
        "/access-request",
        json={
            "envelope_id": str(env_id),
            "purpose": "research",
            "requested_view": "raw_image",
            "job_id": str(uuid.uuid4()),
        },
    )
    assert res.status_code == 403
    assert "expired" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_access_request_scope_mismatch_denied(
    access_test_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, session_factory, _storage, users = access_test_context
    researcher = users["researcher"]

    env_id = uuid.uuid4()
    async with session_factory() as session:
        env = CASDataEnvelope(
            id=env_id,
            object_uri=f"envelopes/{env_id.hex}",
            nonce_hex="0" * 24,
            wrapped_dek="wrapped",
            kek_version=1,
            ciphertext_hash="hash",
            sensitivity_label="restricted",
            dataset_id="restricted-dataset-outside-scope",
        )
        session.add(env)
        await session.commit()

    async def mock_opa(identity, resource, context):
        return PolicyDecision(
            decision="deny",
            reason="Dataset not in approved job scope",
            policy_id=None,
            policy_version=None,
            allowed_view=None,
            decision_expiry=None,
        )

    monkeypatch.setattr("app.api.access.evaluate_access_policy", mock_opa)

    app = client.app
    app.dependency_overrides[get_current_user] = lambda: researcher

    res = client.post(
        "/access-request",
        json={
            "envelope_id": str(env_id),
            "purpose": "research",
            "requested_view": "raw_image",
        },
    )
    assert res.status_code == 403
    assert "scope" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_access_request_opa_unavailable_denied(
    access_test_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, session_factory, _storage, users = access_test_context
    researcher = users["researcher"]

    env_id = uuid.uuid4()
    async with session_factory() as session:
        env = CASDataEnvelope(
            id=env_id,
            object_uri=f"envelopes/{env_id.hex}",
            nonce_hex="0" * 24,
            wrapped_dek="wrapped",
            kek_version=1,
            ciphertext_hash="hash",
            sensitivity_label="restricted",
        )
        session.add(env)
        await session.commit()

    async def mock_opa(identity, resource, context):
        return PolicyDecision(
            decision="deny",
            reason="OPA policy engine unavailable (timeout) -- access denied",
            policy_id=None,
            policy_version=None,
            allowed_view=None,
            decision_expiry=None,
        )

    monkeypatch.setattr("app.api.access.evaluate_access_policy", mock_opa)

    app = client.app
    app.dependency_overrides[get_current_user] = lambda: researcher

    res = client.post(
        "/access-request",
        json={
            "envelope_id": str(env_id),
            "purpose": "research",
            "requested_view": "raw_image",
        },
    )
    assert res.status_code == 403
    assert "unavailable" in res.json()["detail"].lower()
