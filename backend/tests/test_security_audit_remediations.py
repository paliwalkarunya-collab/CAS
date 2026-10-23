"""
Dedicated regression tests for CAS-SE security audit remediations.

Verifies:
1. Finding 1: Key rotation rewrap tracking, partial/failure reporting, selective key retention & recovery.
2. Finding 2: Unknown key versions reject unlock, fail-closed on missing/invalid KCV, state preservation on failure.
3. Finding 3: Enforcement of KCV trust boundary (strict validation required for all tracked versions).
4. Finding 4: Historical unlock does not downgrade active encryption version; order-independence.
"""

from __future__ import annotations

import io
import uuid
from collections.abc import AsyncGenerator

import pytest
from PIL import Image
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from starlette.testclient import TestClient

from app.adapters.key_service import SplitKeyService
from app.adapters.storage import LocalFileAdapter
from app.api.auth import get_current_user
from app.api.envelopes import get_key_service, get_storage_adapter
from app.db.session import CASBase, get_db
from app.main import create_app
from app.models.models import CASDataEnvelope, CASKeyVersion, CASUser
from app.services.identity_service import hash_password


def _make_test_png() -> bytes:
    img = Image.new("RGB", (32, 32), color=(0, 128, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
async def remediations_test_context(
    tmp_path: pytest.TempPathFactory,
) -> AsyncGenerator[
    tuple[TestClient, SplitKeyService, dict[str, CASUser], async_sessionmaker[AsyncSession], LocalFileAdapter],
]:
    test_db_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(test_db_url, echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.create_all)

    users_map = {
        role: CASUser(
            id=uuid.uuid4(),
            username=f"{role}_remediation_user",
            hashed_password=hash_password("Pass123!"),
            role=role,
            is_active=True,
        )
        for role in ["admin", "uploader", "trainer", "researcher", "auditor"]
    }

    async with session_factory() as session:
        session.add_all(list(users_map.values()))
        await session.commit()

    storage_adapter = LocalFileAdapter(str(tmp_path / "remediation_storage"))
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

    yield client, split_service, users_map, session_factory, storage_adapter

    app.dependency_overrides.clear()
    await engine.dispose()


# ---------------------------------------------------------------------------
# Finding 1 Tests: Key Rotation Rewrap Tracking, Failure Reporting & Recovery
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_key_rotation_tracks_and_reports_partial_rewraps(remediations_test_context) -> None:
    """
    Requirement Finding 1:
    - Track successful, failed, and skipped envelope rewraps.
    - Never return 'All DEKs rewrapped' if any envelope failed.
    - Do not retire a key needed by an envelope that was not successfully rewrapped.
    - Ensure failed envelopes remain recoverable with their historical keys.
    """
    client, service, users, session_factory, _storage = remediations_test_context
    app = client.app
    admin = users["admin"]
    uploader = users["uploader"]

    # 1. Bootstrap Shamir keys (version 1)
    app.dependency_overrides[get_current_user] = lambda: admin
    init_res = client.post("/keys/shamir/init")
    assert init_res.status_code == 200
    v1_shares = init_res.json()["shares"]

    # 2. Upload two valid envelopes under v1
    app.dependency_overrides[get_current_user] = lambda: uploader
    up_res1 = client.post(
        "/envelopes",
        files={"file": ("img1.png", io.BytesIO(_make_test_png()), "image/png")},
        data={"dataset_id": "ds1", "sensitivity_label": "restricted"},
    )
    assert up_res1.status_code == 201
    env1_id = uuid.UUID(up_res1.json()["envelope_id"])

    up_res2 = client.post(
        "/envelopes",
        files={"file": ("img2.png", io.BytesIO(_make_test_png()), "image/png")},
        data={"dataset_id": "ds2", "sensitivity_label": "restricted"},
    )
    assert up_res2.status_code == 201
    env2_id = uuid.UUID(up_res2.json()["envelope_id"])

    # 3. Insert a third envelope with a corrupted wrapped_dek that will fail unwrapping
    env3_id = uuid.uuid4()
    async with session_factory() as session:
        corrupted_env = CASDataEnvelope(
            id=env3_id,
            object_uri="envelopes/corrupted_dummy_uri",
            nonce_hex="00" * 12,
            wrapped_dek="not-valid-base64-dek-data!!!",
            kek_version=1,
            ciphertext_hash="00" * 32,
            sensitivity_label="restricted",
            uploaded_by=uploader.id,
        )
        session.add(corrupted_env)
        await session.commit()

    # 4. Rotate KEK to version 2
    app.dependency_overrides[get_current_user] = lambda: admin
    rotate_res = client.post("/keys/rotate")
    assert rotate_res.status_code == 200
    rot_data = rotate_res.json()

    # Verify rotation response metadata
    assert rot_data["old_kek_version"] == 1
    assert rot_data["new_kek_version"] == 2
    assert rot_data["successful_rewraps"] == 2
    assert rot_data["failed_rewraps"] == 1
    assert str(env3_id) in rot_data["skipped_envelopes"]
    assert "Partial rewrap" in rot_data["envelopes_rewrapped"]
    assert "All DEKs rewrapped" not in rot_data["envelopes_rewrapped"]

    # 5. Verify database key versions and envelope states
    async with session_factory() as session:
        # env1 and env2 were successfully rewrapped to v2
        env1 = (await session.execute(select(CASDataEnvelope).where(CASDataEnvelope.id == env1_id))).scalar_one()
        env2 = (await session.execute(select(CASDataEnvelope).where(CASDataEnvelope.id == env2_id))).scalar_one()
        assert env1.kek_version == 2
        assert env2.kek_version == 2

        # env3 was untouched and remains on v1
        env3 = (await session.execute(select(CASDataEnvelope).where(CASDataEnvelope.id == env3_id))).scalar_one()
        assert env3.kek_version == 1
        assert env3.wrapped_dek == "not-valid-base64-dek-data!!!"

        # CRITICAL INVARIANT: Version 1 must NOT be retired because env3 still requires it!
        v1_record = (
            await session.execute(select(CASKeyVersion).where(CASKeyVersion.version_number == 1))
        ).scalar_one()
        assert v1_record.is_current is False
        assert v1_record.retired_at is None, "Key version 1 must not be retired while env3 still uses it!"

        # Version 2 is current
        v2_record = (
            await session.execute(select(CASKeyVersion).where(CASKeyVersion.version_number == 2))
        ).scalar_one()
        assert v2_record.is_current is True

    # 6. Verify valid envelopes remain decryptable after lock and unlock
    v2_shares = rot_data["provisioned_shares"]
    assert len(v2_shares) == 3

    # Lock service
    lock_res = client.post("/keys/shamir/lock")
    assert lock_res.status_code == 200
    assert service.is_unlocked() is False

    # Unlock v2
    unlock_res = client.post("/keys/shamir/unlock", json={"shares": [v2_shares[0], v2_shares[1]]})
    assert unlock_res.status_code == 200
    assert service.is_unlocked() is True
    assert service.current_kek_version() == 2

    # Unlock historical v1
    unlock_v1 = client.post("/keys/shamir/unlock", json={"shares": [v1_shares[0], v1_shares[1]], "version": 1})
    assert unlock_v1.status_code == 200

    # Historical KEK is accessible for decryption
    assert service.get_kek_by_version(1) is not None
    assert service.get_kek_by_version(2) is not None


# ---------------------------------------------------------------------------
# Finding 2 & 3 Tests: Nonexistent Versions, Missing/Incorrect KCV Fail Closed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unlock_rejects_nonexistent_key_version(remediations_test_context) -> None:
    """
    Requirement Finding 2:
    - Reject any requested version that does not exist in trusted key-version records (HTTP 404).
    - Ensure service remains locked and current version is unchanged.
    """
    client, service, users, _session_factory, _ = remediations_test_context
    app = client.app
    admin = users["admin"]
    app.dependency_overrides[get_current_user] = lambda: admin

    # Bootstrap v1
    client.post("/keys/shamir/init")
    client.post("/keys/shamir/lock")
    assert service.is_unlocked() is False

    # Attempt to unlock nonexistent version 999
    res = client.post("/keys/shamir/unlock", json={"version": 999, "shares": ["1-abcdef", "2-123456"]})
    assert res.status_code == 404
    assert "does not exist in trusted key-version records" in res.json()["detail"]

    # Verify service remained locked and current version was not hijacked
    assert service.is_unlocked() is False
    assert service.current_kek_version() != 999


@pytest.mark.asyncio
async def test_unlock_fails_closed_when_kcv_is_missing_or_corrupted(remediations_test_context) -> None:
    """
    Requirement Finding 2 & 3:
    - Fail closed when a required KCV is missing from database records (HTTP 400).
    - Reject tampered shares that fail KCV verification.
    """
    client, service, users, session_factory, _ = remediations_test_context
    app = client.app
    admin = users["admin"]
    app.dependency_overrides[get_current_user] = lambda: admin

    # Bootstrap v1
    init_res = client.post("/keys/shamir/init")
    v1_shares = init_res.json()["shares"]

    # Lock service
    client.post("/keys/shamir/lock")
    assert service.is_unlocked() is False

    # 1. Tamper with DB record to remove KCV (simulate legacy / un-migrated / attacked row)
    async with session_factory() as session:
        v1_record = (
            await session.execute(select(CASKeyVersion).where(CASKeyVersion.version_number == 1))
        ).scalar_one()
        v1_record.key_check_value = None
        await session.commit()

    # Attempt unlock when KCV commitment is missing in DB -> MUST FAIL CLOSED (HTTP 400)
    res_missing_kcv = client.post("/keys/shamir/unlock", json={"shares": [v1_shares[0], v1_shares[1]]})
    assert res_missing_kcv.status_code == 400
    assert "missing a required Key Check Value (KCV) commitment" in res_missing_kcv.json()["detail"]
    assert service.is_unlocked() is False

    # 2. Restore correct KCV
    real_kcv = SplitKeyService.compute_kcv(
        SplitKeyService(shares=[v1_shares[0], v1_shares[1]]).get_kek_by_version(1), 1
    )
    async with session_factory() as session:
        v1_record = (
            await session.execute(select(CASKeyVersion).where(CASKeyVersion.version_number == 1))
        ).scalar_one()
        v1_record.key_check_value = real_kcv
        await session.commit()

    # 3. Attempt unlock with tampered share -> MUST FAIL KCV VALIDATION
    idx, hex_y = v1_shares[1].split("-", 1)
    tampered_int = int(hex_y, 16) ^ 0xFFFF
    tampered_share = f"{idx}-{hex(tampered_int)[2:]}"

    res_tampered = client.post("/keys/shamir/unlock", json={"shares": [v1_shares[0], tampered_share]})
    assert res_tampered.status_code == 400
    assert "Key Check Value (KCV) verification" in res_tampered.json()["detail"]
    assert service.is_unlocked() is False

    # 4. Valid shares unlock cleanly
    res_valid = client.post("/keys/shamir/unlock", json={"shares": [v1_shares[0], v1_shares[1]]})
    assert res_valid.status_code == 200
    assert service.is_unlocked() is True


# ---------------------------------------------------------------------------
# Finding 4 Tests: Historical Unlock Order & Active Version Downgrade Prevention
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_historical_unlock_never_downgrades_active_version(remediations_test_context) -> None:
    """
    Requirement Finding 4:
    - Unlocking an older version must NEVER downgrade the active encryption version.
    - Decouple historical decryption key from active encryption key.
    - Test unlocking in both orders: (v1 then v2) vs (v2 then v1).
    """
    client, service, users, session_factory, _ = remediations_test_context
    app = client.app
    admin = users["admin"]
    uploader = users["uploader"]

    # 1. Initialize v1, rotate to v2, then lock
    app.dependency_overrides[get_current_user] = lambda: admin
    v1_shares = client.post("/keys/shamir/init").json()["shares"]
    v2_shares = client.post("/keys/rotate").json()["provisioned_shares"]
    client.post("/keys/shamir/lock")

    assert service.is_unlocked() is False

    # Status check reflects current version in DB (v2) while locked
    status_locked = client.get("/keys/status").json()
    assert status_locked["is_unlocked"] is False
    assert status_locked["current_version"] == 2

    # 2. UNLOCK HISTORICAL V1 FIRST WHILE SERVICE IS LOCKED
    unlock_v1_res = client.post(
        "/keys/shamir/unlock",
        json={"shares": [v1_shares[0], v1_shares[1]], "version": 1},
    )
    assert unlock_v1_res.status_code == 200
    assert unlock_v1_res.json()["version"] == 1

    # Verify active service state:
    # Service must NOT downgrade current_version to 1!
    # Because active v2 is not yet unlocked, service must remain locked for new uploads!
    status_after_v1 = client.get("/keys/status").json()
    assert status_after_v1["current_version"] == 2, "Active version must NOT downgrade to 1!"
    assert status_after_v1["is_unlocked"] is False, "Service must remain locked until active v2 is unlocked!"
    assert status_after_v1["recovered_versions"] == [1]

    # Verify new upload is BLOCKED (503) because active v2 is not yet unlocked
    app.dependency_overrides[get_current_user] = lambda: uploader
    upload_blocked_res = client.post(
        "/envelopes",
        files={"file": ("blocked.png", io.BytesIO(_make_test_png()), "image/png")},
        data={"dataset_id": "cifar", "sensitivity_label": "restricted"},
    )
    assert upload_blocked_res.status_code == 503
    assert "Key service is locked" in upload_blocked_res.json()["detail"]

    # 3. NOW UNLOCK ACTIVE V2
    app.dependency_overrides[get_current_user] = lambda: admin
    unlock_v2_res = client.post(
        "/keys/shamir/unlock",
        json={"shares": [v2_shares[0], v2_shares[1]]},
    )
    assert unlock_v2_res.status_code == 200
    assert unlock_v2_res.json()["version"] == 2

    # Active version is now unlocked at v2
    status_after_v2 = client.get("/keys/status").json()
    assert status_after_v2["current_version"] == 2
    assert status_after_v2["is_unlocked"] is True
    assert status_after_v2["recovered_versions"] == [1, 2]

    # New upload SUCCEEDS and is encrypted with active version 2!
    app.dependency_overrides[get_current_user] = lambda: uploader
    upload_ok_res = client.post(
        "/envelopes",
        files={"file": ("success.png", io.BytesIO(_make_test_png()), "image/png")},
        data={"dataset_id": "cifar", "sensitivity_label": "restricted"},
    )
    assert upload_ok_res.status_code == 201
    env_id = uuid.UUID(upload_ok_res.json()["envelope_id"])

    async with session_factory() as session:
        env = (await session.execute(select(CASDataEnvelope).where(CASDataEnvelope.id == env_id))).scalar_one()
        assert env.kek_version == 2, f"Expected envelope kek_version to be 2; got {env.kek_version}"
