"""Tests for CAS-SE Phase 6: Audit Hash Chain, Verification, Checkpoint, KEK Rotation, Rewrap, and Split-Key."""

from __future__ import annotations

import base64
import uuid
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from starlette.testclient import TestClient

from app.adapters.key_service import EnvVarKeyService, SplitKeyService
from app.adapters.storage import LocalFileAdapter
from app.api.auth import get_current_user
from app.api.envelopes import get_key_service, get_storage_adapter
from app.core.config import get_settings
from app.db.session import CASBase, get_db
from app.main import create_app
from app.models.models import (
    CASAccessAudit,
    CASDataEnvelope,
    CASUser,
)
from app.services.audit import append_audit_event, verify_chain
from app.services.crypto import (
    build_aad,
    decrypt_payload,
    encrypt_payload,
    generate_dek,
    unwrap_dek,
    wrap_dek,
)
from app.services.identity_service import hash_password
from app.services.key_management import get_key_versions, rotate_kek

settings = get_settings()


# ---------------------------------------------------------------------------
# Unit Tests: Audit Hash Chain Integrity & Tamper Detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_chain_append_and_verify_clean() -> None:
    test_db_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(test_db_url, echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.create_all)

    async with session_factory() as session:
        # Append 3 audit events
        await append_audit_event(
            db=session,
            event_type="login",
            actor_role="admin",
            decision="allow",
            reason="Admin login",
        )
        await append_audit_event(
            db=session,
            event_type="upload",
            actor_role="uploader",
            decision="allow",
            reason="Uploaded sample record",
        )
        await append_audit_event(
            db=session,
            event_type="search",
            actor_role="auditor",
            decision="allow",
            reason="Search query executed",
        )
        await session.commit()

        # Verify chain intact
        is_valid, msg = await verify_chain(session)
        assert is_valid is True
        assert "intact" in msg.lower()

    await engine.dispose()


@pytest.mark.asyncio
async def test_audit_chain_tamper_detection() -> None:
    test_db_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(test_db_url, echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.create_all)

    async with session_factory() as session:
        await append_audit_event(session, "login", decision="allow", reason="Login 1")
        e2 = await append_audit_event(session, "upload", decision="allow", reason="Upload 2")
        await append_audit_event(session, "search", decision="allow", reason="Search 3")
        await session.commit()

        # Tamper with event 2 in the database
        e2.reason = "Tampered reason by attacker"
        await session.commit()

        # Verify chain detects tampering
        is_valid, msg = await verify_chain(session)
        assert is_valid is False
        assert "broken" in msg.lower()

    await engine.dispose()


# ---------------------------------------------------------------------------
# Unit Tests: Key Rewrap & Rotation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_key_rotation_and_dek_rewrap() -> None:
    test_db_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(test_db_url, echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.create_all)

    # Setup simulated key service
    class InMemoryKeyService:
        def __init__(self):
            self.v1 = b"1" * 32
            self.v2 = b"2" * 32
            self.current_version = 1
            self.keys = {1: self.v1}

        def get_current_kek(self):
            return self.keys[self.current_version], self.current_version

        def get_kek_by_version(self, v):
            return self.keys[v]

        def rotate_kek(self):
            self.current_version = 2
            self.keys[2] = self.v2
            return self.v2, 2

    key_service = InMemoryKeyService()
    admin_id = uuid.uuid4()
    raw_payload = b"unmodified ciphertext image data"

    # Create envelope wrapped with KEK v1
    env_id = uuid.uuid4()
    raw_dek = generate_dek()
    aad = build_aad(str(env_id), None, "restricted", 1)
    enc = encrypt_payload(raw_payload, raw_dek, aad)
    wrapped_v1 = wrap_dek(raw_dek, key_service.v1, 1)

    async with session_factory() as session:
        env = CASDataEnvelope(
            id=env_id,
            object_uri="envelopes/test_uri",
            nonce_hex=enc.nonce.hex(),
            wrapped_dek=wrapped_v1.wrapped_dek_b64,
            kek_version=1,
            ciphertext_hash=enc.ciphertext_sha256,
            sensitivity_label="restricted",
        )
        session.add(env)
        await session.commit()

        # Execute KEK rotation
        old_v, new_v = await rotate_kek(key_service, session, admin_id)
        assert old_v == 1
        assert new_v == 2

        # Verify envelope rewrapped to v2
        env_updated = (
            await session.execute(select(CASDataEnvelope).where(CASDataEnvelope.id == env_id))
        ).scalar_one()
        assert env_updated.kek_version == 2
        assert env_updated.wrapped_dek != wrapped_v1.wrapped_dek_b64

        # Verify unwrap with new KEK returns original raw DEK
        unwrapped_dek = unwrap_dek(env_updated.wrapped_dek, key_service.v2)
        assert unwrapped_dek == raw_dek

        # Decrypt payload using unwrapped DEK -> ciphertext never had to change!
        decrypted = decrypt_payload(enc.ciphertext, enc.nonce, unwrapped_dek, aad)
        assert decrypted == raw_payload

        # Verify key versions tracked
        versions = await get_key_versions(session)
        assert len(versions) == 1
        assert versions[0]["version_number"] == 2
        assert versions[0]["is_current"] is True

    await engine.dispose()


# ---------------------------------------------------------------------------
# Unit Tests: SplitKeyService (Shamir Secret Sharing)
# ---------------------------------------------------------------------------


def test_split_key_service_threshold_reconstruction_and_failure() -> None:
    master_secret = "4a" * 32  # 32 bytes hex
    shares = SplitKeyService.generate_shares(master_secret, total=3, threshold=2)
    assert len(shares) == 3

    # Any 2 shares succeed
    service_12 = SplitKeyService(shares=[shares[0], shares[1]], threshold=2)
    kek_12, _ver = service_12.get_current_kek()
    assert kek_12 == bytes.fromhex(master_secret)

    service_23 = SplitKeyService(shares=[shares[1], shares[2]], threshold=2)
    kek_23, _ = service_23.get_current_kek()
    assert kek_23 == bytes.fromhex(master_secret)

    # 1 share is below threshold -> raises ValueError
    with pytest.raises(ValueError, match="requires at least 2 shares"):
        SplitKeyService(shares=[shares[0]], threshold=2)


# ---------------------------------------------------------------------------
# Integration Tests: Phase 6 API Endpoints (Audit, Keys, Policies)
# ---------------------------------------------------------------------------


@pytest.fixture
async def phase6_test_context(
    tmp_path: pytest.TempPathFactory,
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
        username="admin_p6",
        hashed_password=hash_password("Pass123!"),
        role="admin",
        is_active=True,
    )
    auditor_user = CASUser(
        id=uuid.uuid4(),
        username="auditor_p6",
        hashed_password=hash_password("Pass123!"),
        role="auditor",
        is_active=True,
    )
    uploader_user = CASUser(
        id=uuid.uuid4(),
        username="uploader_p6",
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

    yield client, session_factory, users_map

    app.dependency_overrides.clear()
    await engine.dispose()


@pytest.mark.asyncio
async def test_audit_api_query_verify_and_checkpoint(phase6_test_context) -> None:
    client, session_factory, users = phase6_test_context
    auditor = users["auditor"]
    uploader = users["uploader"]
    app = client.app

    # Seed audit events
    async with session_factory() as session:
        await append_audit_event(
            session, "login", actor_id=auditor.id, actor_role="auditor", decision="allow"
        )
        await append_audit_event(
            session, "upload", actor_id=uploader.id, actor_role="uploader", decision="allow"
        )
        await session.commit()

    # 1. Non-auditor / non-admin cannot access /audit
    app.dependency_overrides[get_current_user] = lambda: uploader
    denied = client.get("/audit")
    assert denied.status_code == 403

    # 2. Auditor queries /audit
    app.dependency_overrides[get_current_user] = lambda: auditor
    res = client.get("/audit?event_type=upload")
    assert res.status_code == 200
    events = res.json()
    assert len(events) == 1
    assert events[0]["event_type"] == "upload"

    # 3. Auditor verifies chain integrity
    verify_res = client.get("/audit/verify")
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["is_valid"] is True
    assert verify_data["events_verified"] >= 2

    # 4. Auditor exports signed checkpoint
    checkpoint_res = client.get("/audit/checkpoint")
    assert checkpoint_res.status_code == 200
    cp_data = checkpoint_res.json()
    assert cp_data["total_events"] >= 2
    assert "checkpoint_signature" in cp_data
    assert len(cp_data["checkpoint_signature"]) == 64


@pytest.mark.asyncio
async def test_keys_rotate_api(phase6_test_context) -> None:
    client, session_factory, users = phase6_test_context
    admin = users["admin"]
    uploader = users["uploader"]
    app = client.app

    # 1. Non-admin cannot rotate keys
    app.dependency_overrides[get_current_user] = lambda: uploader
    denied = client.post("/keys/rotate")
    assert denied.status_code == 403

    # 2. Admin rotates keys
    app.dependency_overrides[get_current_user] = lambda: admin
    res = client.post("/keys/rotate")
    assert res.status_code == 200
    data = res.json()
    assert data["old_kek_version"] == 1
    assert data["new_kek_version"] == 2

    # 3. List key versions
    list_res = client.get("/keys")
    assert list_res.status_code == 200
    versions = list_res.json()
    assert len(versions) >= 1

    # 4. Verify audit event recorded key_rotate
    async with session_factory() as session:
        audit_res = await session.execute(
            select(CASAccessAudit).where(CASAccessAudit.event_type == "key_rotate")
        )
        audit_event = audit_res.scalar_one()
        assert audit_event.decision == "allow"
        assert audit_event.actor_id == admin.id


@pytest.mark.asyncio
async def test_policies_crud_api(phase6_test_context) -> None:
    client, _session_factory, users = phase6_test_context
    admin = users["admin"]
    auditor = users["auditor"]
    app = client.app

    rego_sample = """
    package cas_se.test
    default allow := true
    """

    # 1. Admin creates policy
    app.dependency_overrides[get_current_user] = lambda: admin
    create_res = client.post(
        "/policies",
        json={
            "name": "hospital_radiology_policy",
            "description": "Access policy for radiology scans",
            "rego_policy": rego_sample,
        },
    )
    assert create_res.status_code == 201
    policy_data = create_res.json()
    policy_id = policy_data["policy_id"]
    assert policy_data["name"] == "hospital_radiology_policy"
    assert policy_data["latest_version"] == 1

    # 2. Auditor lists policies
    app.dependency_overrides[get_current_user] = lambda: auditor
    list_res = client.get("/policies")
    assert list_res.status_code == 200
    pol_names = [p["name"] for p in list_res.json()]
    assert "hospital_radiology_policy" in pol_names

    # 3. Get policy detail
    detail_res = client.get(f"/policies/{policy_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["policy_id"] == policy_id
