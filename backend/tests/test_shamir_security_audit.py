"""Dedicated Security, Persistence, and Concurrency Audit Tests for Shamir Secret Sharing."""

from __future__ import annotations

import io
import os
import uuid
from collections.abc import AsyncGenerator
from concurrent.futures import ThreadPoolExecutor

import pytest
from PIL import Image
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from starlette.testclient import TestClient

from app.adapters.key_service import _SHAMIR_PRIME, KeyServiceLockedError, SplitKeyService
from app.adapters.storage import LocalFileAdapter
from app.api.auth import get_current_user
from app.api.envelopes import get_key_service, get_storage_adapter
from app.db.session import CASBase, get_db
from app.main import create_app
from app.models.models import CASAccessAudit, CASDataEnvelope, CASUser
from app.services.crypto import (
    build_aad,
    decrypt_payload,
    encrypt_payload,
    generate_dek,
    unwrap_dek,
    wrap_dek,
)
from app.services.identity_service import hash_password


def _make_test_png() -> bytes:
    img = Image.new("RGB", (32, 32), color=(0, 128, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
async def audit_test_context(
    tmp_path: pytest.TempPathFactory,
) -> AsyncGenerator[tuple[TestClient, SplitKeyService, dict[str, CASUser], async_sessionmaker[AsyncSession]],]:
    test_db_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(test_db_url, echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.create_all)

    users_map = {
        role: CASUser(
            id=uuid.uuid4(),
            username=f"{role}_audit_user",
            hashed_password=hash_password("Pass123!"),
            role=role,
            is_active=True,
        )
        for role in ["admin", "uploader", "trainer", "researcher", "auditor"]
    }

    async with session_factory() as session:
        session.add_all(list(users_map.values()))
        await session.commit()

    storage_adapter = LocalFileAdapter(str(tmp_path / "audit_storage"))
    split_service = SplitKeyService(threshold=2, total=3)

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
    app.dependency_overrides[get_key_service] = lambda: split_service

    client = TestClient(app)

    yield client, split_service, users_map, session_factory

    app.dependency_overrides.clear()
    await engine.dispose()


# ---------------------------------------------------------------------------
# 1. API Authorization: Test Every Role and Unauthenticated on Key Endpoints
# ---------------------------------------------------------------------------


def test_api_authorization_matrix_on_key_endpoints(audit_test_context) -> None:
    """Requirement: Unauthenticated requests and non-admin roles MUST be blocked."""
    client, _service, users, _session_factory = audit_test_context
    app = client.app

    endpoints = [
        ("GET", "/keys/status", None),
        ("POST", "/keys/shamir/init", None),
        ("POST", "/keys/shamir/unlock", {"shares": ["1-abc", "2-def"]}),
        ("POST", "/keys/shamir/lock", None),
        ("POST", "/keys/rotate", None),
        ("GET", "/keys", None),
    ]

    for method, path, json_body in endpoints:
        # 1. Unauthenticated -> 401
        app.dependency_overrides.pop(get_current_user, None)
        res_unauth = client.request(method, path, json=json_body)
        assert res_unauth.status_code == 401, f"{method} {path} should be 401 without auth"

        # 2. Non-admin roles (uploader, trainer, researcher, auditor) -> 403
        for non_admin_role in ["uploader", "trainer", "researcher", "auditor"]:
            app.dependency_overrides[get_current_user] = lambda u=users[non_admin_role]: u
            res_forbidden = client.request(method, path, json=json_body)
            assert (
                res_forbidden.status_code == 403
            ), f"{method} {path} should be 403 for role {non_admin_role}"


# ---------------------------------------------------------------------------
# 2. Restart, Persistence & Historical Decryption
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_restart_and_historical_recovery(audit_test_context) -> None:
    """Requirement: Test envelope creation, rotation, backend restart, and recovery of both versions."""
    client, service, users, session_factory = audit_test_context
    app = client.app
    admin = users["admin"]
    uploader = users["uploader"]

    # 1. Bootstrap Shamir keys for version 1
    app.dependency_overrides[get_current_user] = lambda: admin
    init_res = client.post("/keys/shamir/init")
    assert init_res.status_code == 200
    v1_shares = init_res.json()["shares"]

    # 2. Upload an envelope under KEK v1
    app.dependency_overrides[get_current_user] = lambda: uploader
    upload_res = client.post(
        "/envelopes",
        files={"file": ("historical_v1.png", io.BytesIO(_make_test_png()), "image/png")},
        data={"dataset_id": "radiology", "sensitivity_label": "restricted"},
    )
    assert upload_res.status_code == 201
    env_id = uuid.UUID(upload_res.json()["envelope_id"])

    # Verify envelope stored in DB with kek_version = 1
    async with session_factory() as session:
        env = (
            await session.execute(select(CASDataEnvelope).where(CASDataEnvelope.id == env_id))
        ).scalar_one()
        assert env.kek_version == 1
        assert len(env.wrapped_dek) > 0

    # 3. Rotate to KEK v2
    app.dependency_overrides[get_current_user] = lambda: admin
    rotate_res = client.post("/keys/rotate")
    assert rotate_res.status_code == 200
    rot_data = rotate_res.json()
    assert rot_data["new_kek_version"] == 2
    v2_shares = rot_data["provisioned_shares"]

    # Create an un-rewrapped envelope simulating a retained historical v1 envelope
    raw_payload_v1 = b"Historical dataset payload sealed with KEK v1"
    raw_dek_v1 = generate_dek()
    aad_v1 = build_aad("historical-env-001", None, "restricted", 1)
    enc_v1 = encrypt_payload(raw_payload_v1, raw_dek_v1, aad_v1)
    v1_kek = service.get_kek_by_version(1)
    wrapped_v1_dek = wrap_dek(raw_dek_v1, v1_kek, 1).wrapped_dek_b64

    # 4. SIMULATE RESTART: Create a brand new SplitKeyService instance (memory completely wiped)
    restarted_service = SplitKeyService(threshold=2, total=3)
    assert restarted_service.is_unlocked() is False
    assert restarted_service.get_status()["recovered_versions"] == []

    # Inject restarted service into application state
    app.dependency_overrides[get_key_service] = lambda: restarted_service

    # Status check reflects LOCKED and current version from DB (v2)
    status_res = client.get("/keys/status")
    assert status_res.status_code == 200
    assert status_res.json()["is_unlocked"] is False
    assert status_res.json()["current_version"] == 2

    # Attempting to access data before unlock fails closed (503)
    with pytest.raises(KeyServiceLockedError):
        restarted_service.unwrap_dek(wrapped_v1_dek, version=1)

    # 5. Custodians unlock KEK v2 (without specifying version, defaults to DB current version 2)
    unlock_v2_res = client.post(
        "/keys/shamir/unlock",
        json={"shares": [v2_shares[0], v2_shares[1]]},
    )
    assert unlock_v2_res.status_code == 200
    assert unlock_v2_res.json()["version"] == 2
    assert restarted_service.is_unlocked() is True
    assert restarted_service.current_kek_version() == 2

    # Attempting to unwrap historical v1 envelope fails until v1 shares are provided
    with pytest.raises(KeyError, match="Split-key KEK version 1 not available"):
        restarted_service.unwrap_dek(wrapped_v1_dek, version=1)

    # 6. Custodians unlock historical KEK v1
    unlock_v1_res = client.post(
        "/keys/shamir/unlock",
        json={"shares": [v1_shares[1], v1_shares[2]], "version": 1},
    )
    assert unlock_v1_res.status_code == 200
    assert unlock_v1_res.json()["version"] == 1
    # Both versions are now recovered in memory
    assert restarted_service.get_status()["recovered_versions"] == [1, 2]
    # Primary active version remains v2 for new operations
    assert restarted_service.current_kek_version() == 2

    # 7. Decrypt historical envelope using recovered v1 key
    unwrapped_dek = restarted_service.unwrap_dek(wrapped_v1_dek, version=1)
    assert unwrapped_dek == raw_dek_v1
    decrypted_v1 = decrypt_payload(enc_v1.ciphertext, enc_v1.nonce, unwrapped_dek, aad_v1)
    assert decrypted_v1 == raw_payload_v1


# ---------------------------------------------------------------------------
# 3. Share Leakage & Audit Sanitization Check
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shares_and_keys_never_leak_in_errors_or_audit(audit_test_context) -> None:
    """Requirement: Malformed shares, corrupted hex, or invalid inputs must not leak into exceptions or audit logs."""
    client, _service, users, session_factory = audit_test_context
    app = client.app
    admin = users["admin"]
    app.dependency_overrides[get_current_user] = lambda: admin

    # Secret string that should NEVER appear in logs or responses
    secret_canary = "deadbeefcafebabe0123456789abcdef"

    # 1. Invalid hex share
    res_bad_hex = client.post(
        "/keys/shamir/unlock",
        json={"shares": [f"1-not_valid_hex_{secret_canary}", "2-abcdef1234567890"]},
    )
    assert res_bad_hex.status_code == 400
    assert secret_canary not in res_bad_hex.text

    # 2. Out of field range share
    out_of_field_hex = hex(_SHAMIR_PRIME + 9999)[2:]
    res_bad_range = client.post(
        "/keys/shamir/unlock",
        json={"shares": [f"1-{out_of_field_hex}", "2-abcdef1234567890"]},
    )
    assert res_bad_range.status_code == 400
    assert out_of_field_hex not in res_bad_range.text

    # 3. Malformed share missing hyphen
    res_malformed = client.post(
        "/keys/shamir/unlock",
        json={"shares": [f"canary_string_{secret_canary}", "2-abcdef1234567890"]},
    )
    assert res_malformed.status_code == 400
    assert secret_canary not in res_malformed.text

    # 4. Verify DB Audit log entries do not leak canary
    async with session_factory() as session:
        audits = (
            await session.execute(
                select(CASAccessAudit).where(CASAccessAudit.event_type == "key_rotate")
            )
        ).scalars().all()
        for audit in audits:
            assert secret_canary not in (audit.reason or "")
            assert out_of_field_hex not in (audit.reason or "")


# ---------------------------------------------------------------------------
# 4. Concurrency & Thread-Safety Stress Test
# ---------------------------------------------------------------------------


def test_split_key_concurrent_access_stress() -> None:
    """Stress test concurrent lock, unlock, and KEK retrieval across multiple threads."""
    service = SplitKeyService(threshold=2, total=3)
    secret = os.urandom(32)
    shares = SplitKeyService.generate_shares(secret.hex(), total=3, threshold=2)

    errors: list[Exception] = []

    def worker_unlock():
        try:
            service.unlock([shares[0], shares[1]])
        except Exception as e:
            errors.append(e)

    def worker_lock():
        try:
            service.lock()
        except Exception as e:
            errors.append(e)

    def worker_status():
        try:
            _ = service.get_status()
        except Exception as e:
            errors.append(e)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = []
        for _ in range(50):
            futures.append(pool.submit(worker_unlock))
            futures.append(pool.submit(worker_status))
            futures.append(pool.submit(worker_lock))
            futures.append(pool.submit(worker_status))

        for f in futures:
            f.result()

    # No race conditions or unhandled crashes in internal dictionaries
    assert len(errors) == 0


def test_historical_envelope_decryption_and_cross_version_resilience(tmp_path) -> None:
    """Verify that historical envelopes remain fully decryptable across KEK rotations
    and adapter lifecycles using isolated, disposable test fixtures without real databases or .env."""
    from cryptography.exceptions import InvalidTag

    storage = LocalFileAdapter(str(tmp_path / "hist_storage"))

    # 1. Generate synthetic historical KEK v1 and new KEK v2
    kek_v1 = os.urandom(32)
    kek_v2 = os.urandom(32)
    dek = generate_dek()

    # 2. Encrypt synthetic test payload bound to envelope metadata
    payload_content = b"Synthetic DICOM test payload: " + os.urandom(64)
    envelope_id = uuid.uuid4()
    aad = build_aad(
        envelope_id=str(envelope_id),
        policy_id=None,
        sensitivity_label="restricted",
        encryption_version=1,
    )
    enc = encrypt_payload(payload_content, dek, aad)
    obj_key = f"envelopes/{uuid.uuid4().hex}.enc"
    storage.put_object(obj_key, enc.ciphertext)

    # 3. Wrap DEK under historical KEK v1
    wrapped_v1 = wrap_dek(dek, kek_v1, kek_version=1)

    # 4. Prove unwrap and decryption succeeds with historical KEK v1
    unwrapped_dek_v1 = unwrap_dek(wrapped_v1.wrapped_dek_b64, kek_v1)
    recovered_pt_v1 = decrypt_payload(storage.get_object(obj_key), enc.nonce, unwrapped_dek_v1, aad)
    assert recovered_pt_v1 == payload_content

    # 5. Prove that unwrap fails closed with InvalidTag if attempted with wrong KEK (v2)
    with pytest.raises(InvalidTag):
        unwrap_dek(wrapped_v1.wrapped_dek_b64, kek_v2)

    # 6. Simulate key rotation rewrap: unwrap with v1, rewrap under v2
    wrapped_v2 = wrap_dek(unwrapped_dek_v1, kek_v2, kek_version=2)
    unwrapped_dek_v2 = unwrap_dek(wrapped_v2.wrapped_dek_b64, kek_v2)
    recovered_pt_v2 = decrypt_payload(storage.get_object(obj_key), enc.nonce, unwrapped_dek_v2, aad)
    assert recovered_pt_v2 == payload_content

    # 7. Multi-version SplitKeyService lifecycle verification
    split_service = SplitKeyService(threshold=2, total=3)
    # Initialize fresh SplitKeyService (v1)
    v1_ver, v1_shares = split_service.init_new_key()
    assert v1_ver == 1
    # Rotate to v2
    _new_kek, v2_ver = split_service.rotate_kek()
    assert v2_ver == 2
    v2_shares = split_service.get_last_generated_shares()
    assert v2_shares is not None

    # Cold restart: lock and clear memory
    split_service.lock()
    assert split_service.is_unlocked() is False

    # Attempt retrieval while locked fails closed
    with pytest.raises(KeyServiceLockedError):
        split_service.get_kek_by_version(1)
    with pytest.raises(KeyServiceLockedError):
        split_service.get_kek_by_version(2)

    # Custodian unlock of v2
    split_service.unlock([v2_shares[0], v2_shares[1]], version=2)
    assert split_service.is_unlocked() is True
    assert 2 in split_service.get_status()["recovered_versions"]

    # Custodian recovery of historical v1
    split_service.unlock([v1_shares[0], v1_shares[1]], version=1)
    assert 1 in split_service.get_status()["recovered_versions"]

    # Both versions are accessible
    assert split_service.get_kek_by_version(1) is not None
    assert split_service.get_kek_by_version(2) is not None

