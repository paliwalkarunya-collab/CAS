"""Tests for KeyServiceAdapter, EnvVarKeyService, and SplitKeyService (Shamir Secret Sharing)."""

from __future__ import annotations

import base64
import io
import os
import uuid
from collections.abc import AsyncGenerator

import pytest
from PIL import Image
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from starlette.testclient import TestClient

from app.adapters.factory import build_key_service
from app.adapters.key_service import (
    _SHAMIR_PRIME,
    EnvVarKeyService,
    KeyServiceAdapter,
    KeyServiceLockedError,
    SplitKeyService,
)
from app.adapters.storage import LocalFileAdapter
from app.api.auth import get_current_user
from app.api.envelopes import get_key_service, get_storage_adapter
from app.core.config import Settings
from app.db.session import CASBase, get_db
from app.main import create_app
from app.models.models import CASUser
from app.services.crypto import (
    build_aad,
    decrypt_payload,
    encrypt_payload,
    generate_dek,
)
from app.services.identity_service import hash_password

# ---------------------------------------------------------------------------
# Unit Tests: EnvVarKeyService (Baseline & Regression Preservation)
# ---------------------------------------------------------------------------


def test_key_service_protocol_compliance(monkeypatch: pytest.MonkeyPatch) -> None:
    raw_key = os.urandom(32)
    b64_key = base64.b64encode(raw_key).decode()
    monkeypatch.setenv("CAS_KEK_V1", b64_key)
    monkeypatch.setenv("CAS_KEK_CURRENT_VERSION", "1")

    service = EnvVarKeyService()
    assert isinstance(service, KeyServiceAdapter)
    assert service.is_unlocked() is True
    status = service.get_status()
    assert status["adapter"] == "env"
    assert status["is_unlocked"] is True


def test_env_var_key_service_retrieval_and_rotation(monkeypatch: pytest.MonkeyPatch) -> None:
    raw_key_v1 = os.urandom(32)
    raw_key_v2 = os.urandom(32)
    monkeypatch.setenv("CAS_KEK_V1", base64.b64encode(raw_key_v1).decode())
    monkeypatch.setenv("CAS_KEK_V2", base64.b64encode(raw_key_v2).decode())
    monkeypatch.setenv("CAS_KEK_CURRENT_VERSION", "2")

    service = EnvVarKeyService()
    current_key, current_ver = service.get_current_kek()
    assert current_ver == 2
    assert current_key == raw_key_v2
    assert service.get_kek_by_version(1) == raw_key_v1

    # Rotation
    new_key, new_ver = service.rotate_kek()
    assert new_ver == 3
    assert len(new_key) == 32
    assert service.get_current_kek() == (new_key, 3)
    assert service.get_kek_by_version(2) == raw_key_v2


def test_env_var_key_service_invalid_version_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAS_KEK_CURRENT_VERSION", "not-a-number")
    with pytest.raises(OSError, match="must be an integer"):
        EnvVarKeyService()


def test_env_var_key_service_missing_current_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAS_KEK_CURRENT_VERSION", "99")
    with pytest.raises(OSError, match="CAS_KEK_V99 is not set"):
        EnvVarKeyService()


# ---------------------------------------------------------------------------
# Unit Tests: SplitKeyService Mathematical Correctness & Share Combinations
# ---------------------------------------------------------------------------


def test_split_key_service_threshold_reconstruction() -> None:
    secret_bytes = os.urandom(32)
    secret_hex = secret_bytes.hex()

    shares = SplitKeyService.generate_shares(secret_hex, total=3, threshold=2)
    assert len(shares) == 3

    # Reconstruct with 2 shares (shares 0 and 1)
    split_service_1 = SplitKeyService(shares=[shares[0], shares[1]], threshold=2)
    kek_1, ver_1 = split_service_1.get_current_kek()
    assert kek_1 == secret_bytes
    assert ver_1 == 1

    # Reconstruct with different 2 shares (shares 1 and 2)
    split_service_2 = SplitKeyService(shares=[shares[1], shares[2]], threshold=2)
    kek_2, _ver_2 = split_service_2.get_current_kek()
    assert kek_2 == secret_bytes

    # Insufficient shares raises error
    with pytest.raises(ValueError, match="requires at least 2 shares"):
        SplitKeyService(shares=[shares[0]], threshold=2)


def test_split_key_all_pair_combinations_reconstruct_identical_key() -> None:
    """Requirement: verify recovery with every valid pair: (1,2), (1,3), (2,3), reverse, all 3."""
    secret = os.urandom(32)
    shares = SplitKeyService.generate_shares(secret.hex(), total=3, threshold=2)
    s1, s2, s3 = shares[0], shares[1], shares[2]

    # Test (1, 2)
    svc_12 = SplitKeyService(shares=[s1, s2], threshold=2)
    assert svc_12.get_current_kek()[0] == secret

    # Test (1, 3)
    svc_13 = SplitKeyService(shares=[s1, s3], threshold=2)
    assert svc_13.get_current_kek()[0] == secret

    # Test (2, 3)
    svc_23 = SplitKeyService(shares=[s2, s3], threshold=2)
    assert svc_23.get_current_kek()[0] == secret

    # Test reverse order (3, 1) - Lagrange interpolation is order-independent
    svc_31 = SplitKeyService(shares=[s3, s1], threshold=2)
    assert svc_31.get_current_kek()[0] == secret

    # Test all 3 shares provided together
    svc_123 = SplitKeyService(shares=[s1, s2, s3], threshold=2)
    assert svc_123.get_current_kek()[0] == secret


def test_split_key_single_share_insufficient() -> None:
    """Requirement: 1 share alone cannot reconstruct the KEK."""
    secret = os.urandom(32)
    shares = SplitKeyService.generate_shares(secret.hex(), total=3, threshold=2)

    # Constructor rejects 1 share
    with pytest.raises(ValueError, match="requires at least 2 shares"):
        SplitKeyService(shares=[shares[0]], threshold=2)

    # unlock rejects 1 share
    svc = SplitKeyService()
    with pytest.raises(ValueError, match="requires at least 2 shares"):
        svc.unlock([shares[0]])

    with pytest.raises(ValueError, match="requires at least 2 shares"):
        svc.unlock([])


def test_split_key_duplicate_shares_rejected() -> None:
    """Requirement: Reject duplicate shares safely."""
    secret = os.urandom(32)
    shares = SplitKeyService.generate_shares(secret.hex(), total=3, threshold=2)

    # Submitting identical share twice to spoof threshold
    with pytest.raises(ValueError, match=r"Duplicate share.*detected"):
        SplitKeyService(shares=[shares[0], shares[0]], threshold=2)

    svc = SplitKeyService()
    with pytest.raises(ValueError, match=r"Duplicate share.*detected"):
        svc.unlock([shares[1], shares[1]])


def test_split_key_malformed_and_out_of_range_shares_rejected() -> None:
    """Requirement: Validate share format, threshold, share count, and field arithmetic."""
    secret = os.urandom(32)
    shares = SplitKeyService.generate_shares(secret.hex(), total=3, threshold=2)
    valid_share = shares[0]

    # No dash delimiter
    with pytest.raises(ValueError, match=r"Malformed split-key share format"):
        SplitKeyService(shares=["not_a_share", valid_share], threshold=2)

    # x = 0 (x=0 corresponds to the polynomial intercept / secret itself, forbidden for custodians)
    with pytest.raises(ValueError, match=r"Share x-coordinate out of valid range"):
        SplitKeyService(shares=["0-abcdef0123", valid_share], threshold=2)

    # Negative x or empty x
    with pytest.raises(
        ValueError, match=r"(Invalid share x-coordinate|Malformed split-key share format)"
    ):
        SplitKeyService(shares=["-1-abcdef0123", valid_share], threshold=2)

    # Non-hex y
    with pytest.raises(ValueError, match=r"Invalid share y-coordinate hex format"):
        SplitKeyService(shares=["1-not_a_hex_value", valid_share], threshold=2)

    # y >= prime (out of finite-field range)
    out_of_field_y = hex(_SHAMIR_PRIME + 10)[2:]
    with pytest.raises(ValueError, match=r"out of field range"):
        SplitKeyService(shares=[f"1-{out_of_field_y}", valid_share], threshold=2)


def test_split_key_tampered_shares_detected() -> None:
    """Requirement: Incorrect shares must not silently yield the original secret."""
    secret = os.urandom(32)
    shares = SplitKeyService.generate_shares(secret.hex(), total=3, threshold=2)
    s1 = shares[0]

    # Tamper with the y coordinate of share 2
    idx, hex_val = shares[1].split("-", 1)
    tampered_int = (int(hex_val, 16) ^ 0xFFFF) % _SHAMIR_PRIME
    tampered_s2 = f"{idx}-{hex(tampered_int)[2:]}"

    try:
        svc = SplitKeyService(shares=[s1, tampered_s2], threshold=2)
        recovered_kek, _ = svc.get_current_kek()
        # If mathematically it didn't overflow 2^256, it must NOT match the original secret
        assert recovered_kek != secret
    except ValueError as e:
        # If the tampered interpolation exceeds 2^256, it is cleanly caught
        assert "out of 256-bit range" in str(e)


def test_split_key_threshold_validation_errors() -> None:
    """Requirement: Validate threshold and share count configurations."""
    # Threshold < 2 rejected
    with pytest.raises(ValueError, match="threshold must be >= 2"):
        SplitKeyService(threshold=1)

    # Total < threshold rejected
    with pytest.raises(ValueError, match=r"total shares .* must be >= threshold"):
        SplitKeyService(threshold=3, total=2)

    # generate_shares with invalid secret length rejected
    with pytest.raises(ValueError, match=r"Secret must be exactly 32 bytes"):
        SplitKeyService.generate_shares("abcd" * 8, total=3, threshold=2)


# ---------------------------------------------------------------------------
# Unit Tests: Lifecycle, In-Memory Locking, Fail-Closed Behavior
# ---------------------------------------------------------------------------


def test_split_key_lock_unlock_lifecycle() -> None:
    """Requirement: Clear temporary secret buffers and enforce fail-closed state when locked."""
    secret = os.urandom(32)
    shares = SplitKeyService.generate_shares(secret.hex(), total=3, threshold=2)

    # 1. Starts locked if initialized with no shares
    service = SplitKeyService()
    assert service.is_unlocked() is False
    status = service.get_status()
    assert status["is_unlocked"] is False
    assert status["adapter"] == "split"
    assert status["shares_provided_count"] == 0

    # 2. Methods raise KeyServiceLockedError when locked
    with pytest.raises(KeyServiceLockedError, match="SplitKeyService is locked"):
        service.get_current_kek()

    with pytest.raises(KeyServiceLockedError, match="SplitKeyService is locked"):
        service.wrap_dek(b"d" * 32)

    with pytest.raises(KeyServiceLockedError, match="SplitKeyService is locked"):
        service.unwrap_dek("dummy", 1)

    with pytest.raises(KeyServiceLockedError, match="SplitKeyService is locked"):
        service.get_kek_by_version(1)

    # 3. Unlock with threshold shares
    kek, ver = service.unlock([shares[0], shares[1]])
    assert kek == secret
    assert ver == 1
    assert service.is_unlocked() is True
    assert service.get_status()["is_unlocked"] is True
    assert service.get_status()["shares_provided_count"] == 2
    assert service.get_current_kek()[0] == secret

    # 4. Lock purges secret from memory
    service.lock()
    assert service.is_unlocked() is False
    assert service.get_status()["is_unlocked"] is False

    with pytest.raises(KeyServiceLockedError):
        service.get_current_kek()


def test_split_key_init_new_key_and_rotation_lifecycle() -> None:
    """Requirement: Provision fresh KEK and shares, preserve historical versions."""
    service = SplitKeyService()
    assert service.is_unlocked() is False

    # Initialize fresh key
    v1_num, provisioned_shares = service.init_new_key(total=3, threshold=2)
    assert len(provisioned_shares) == 3
    assert service.is_unlocked() is True
    v1_kek, current_ver = service.get_current_kek()
    assert v1_num == 1
    assert current_ver == 1
    assert len(v1_kek) == 32

    # Verify provisioned shares can independently reconstruct v1_kek
    reconstructed = SplitKeyService(
        shares=[provisioned_shares[0], provisioned_shares[2]], threshold=2
    ).get_current_kek()[0]
    assert reconstructed == v1_kek

    # Rotate KEK
    v2_kek, v2_num = service.rotate_kek()
    assert v2_num == 2
    assert v2_kek != v1_kek
    assert len(v2_kek) == 32
    assert service.current_kek_version() == 2

    # Historical v1 is still retained in memory for decrypting older records
    assert service.get_kek_by_version(1) == v1_kek
    assert service.get_kek_by_version(2) == v2_kek

    # New shares were generated for v2
    v2_shares = service.get_last_generated_shares()
    assert v2_shares is not None
    assert len(v2_shares) == 3
    reconstructed_v2 = SplitKeyService(
        shares=[v2_shares[1], v2_shares[2]], threshold=2
    ).get_current_kek()[0]
    assert reconstructed_v2 == v2_kek


def test_split_key_envelope_crypto_round_trip() -> None:
    """Requirement: Actual encryption and decryption using the Shamir adapter and rotation."""
    service = SplitKeyService()
    service.init_new_key(total=3, threshold=2)
    assert service.is_unlocked() is True

    # 1. Upload/Encrypt flow: generate DEK, wrap with SplitKeyService v1
    raw_dek = generate_dek()
    wrapped_dek_b64, v1 = service.wrap_dek(raw_dek)
    assert v1 == 1

    payload = b"Top secret medical image dataset payload"
    aad = build_aad("envelope-101", None, "restricted", 1)
    encrypted = encrypt_payload(payload, raw_dek, aad)

    # 2. Key Rotation occurs: service moves to v2
    service.rotate_kek()
    assert service.current_kek_version() == 2

    # 3. Access/Decryption flow: envelope created under v1 is still unwrapped using v1 KEK
    unwrapped_dek = service.unwrap_dek(wrapped_dek_b64, version=1)
    assert unwrapped_dek == raw_dek

    # 4. Decrypt payload with unwrapped DEK
    decrypted = decrypt_payload(encrypted.ciphertext, encrypted.nonce, unwrapped_dek, aad)
    assert decrypted == payload


# ---------------------------------------------------------------------------
# Unit Tests: Adapter Factory & Configuration Parsing
# ---------------------------------------------------------------------------


def test_adapter_factory_split_mode_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement: KEY_SERVICE_ADAPTER=split selects the Shamir-backed key service."""
    # Split with pre-configured shares
    secret = os.urandom(32)
    shares = SplitKeyService.generate_shares(secret.hex(), total=3, threshold=2)

    settings_with_shares = Settings(
        KEY_SERVICE_ADAPTER="split",
        SPLIT_KEY_SHARES=shares[:2],
        SPLIT_KEY_THRESHOLD=2,
    )
    adapter = build_key_service(settings_with_shares)
    assert isinstance(adapter, SplitKeyService)
    assert adapter.is_unlocked() is True
    assert adapter.get_current_kek()[0] == secret

    # Split without pre-configured shares (starts locked)
    settings_locked = Settings(
        KEY_SERVICE_ADAPTER="split",
        SPLIT_KEY_SHARES=[],
        SPLIT_KEY_THRESHOLD=2,
    )
    adapter_locked = build_key_service(settings_locked)
    assert isinstance(adapter_locked, SplitKeyService)
    assert adapter_locked.is_unlocked() is False

    # Invalid adapter rejected safely
    # Invalid adapter rejected safely by Pydantic validation
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="Unknown key_service_adapter"):
        Settings(KEY_SERVICE_ADAPTER="unsupported_adapter")


# ---------------------------------------------------------------------------
# Integration Tests: FastAPI Endpoints with SplitKeyService (HTTP, Auth, Fail-Closed)
# ---------------------------------------------------------------------------


@pytest.fixture
async def shamir_test_context(
    tmp_path: pytest.TempPathFactory,
) -> AsyncGenerator[tuple[TestClient, SplitKeyService, dict[str, CASUser]],]:
    test_db_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(test_db_url, echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.create_all)

    admin_user = CASUser(
        id=uuid.uuid4(),
        username="admin_shamir",
        hashed_password=hash_password("Pass123!"),
        role="admin",
        is_active=True,
    )
    uploader_user = CASUser(
        id=uuid.uuid4(),
        username="uploader_shamir",
        hashed_password=hash_password("Pass123!"),
        role="uploader",
        is_active=True,
    )
    trainer_user = CASUser(
        id=uuid.uuid4(),
        username="trainer_shamir",
        hashed_password=hash_password("Pass123!"),
        role="trainer",
        is_active=True,
    )

    users_map = {
        "admin": admin_user,
        "uploader": uploader_user,
        "trainer": trainer_user,
    }

    async with session_factory() as session:
        session.add_all(list(users_map.values()))
        await session.commit()

    storage_adapter = LocalFileAdapter(str(tmp_path / "shamir_storage"))
    # SplitKeyService starts locked without shares
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

    yield client, split_service, users_map

    app.dependency_overrides.clear()
    await engine.dispose()


def test_shamir_api_status_endpoint(shamir_test_context) -> None:
    """Requirement: Non-sensitive key-version metadata and status without secrets."""
    client, _service, users = shamir_test_context
    app = client.app
    app.dependency_overrides[get_current_user] = lambda: users["admin"]

    res = client.get("/keys/status")
    assert res.status_code == 200
    data = res.json()
    assert data["adapter"] == "split"
    assert data["is_unlocked"] is False
    assert data["threshold"] == 2
    assert data["total_shares"] == 3
    assert data["shares_provided_count"] == 0
    # No secret fields leaked
    assert "secret" not in data
    assert "kek" not in data
    assert "shares" not in data


def _make_test_png() -> bytes:
    img = Image.new("RGB", (32, 32), color=(255, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_shamir_api_fail_closed_503_when_locked(shamir_test_context) -> None:
    """Requirement: Fail-closed behavior with clear 503 error if service is locked."""
    client, service, users = shamir_test_context
    app = client.app
    assert service.is_unlocked() is False

    # Attempting to upload when key service is locked must return 503 Service Unavailable
    app.dependency_overrides[get_current_user] = lambda: users["uploader"]
    dummy_file = io.BytesIO(_make_test_png())
    upload_res = client.post(
        "/envelopes",
        files={"file": ("test.png", dummy_file, "image/png")},
        data={"dataset_id": "cifar10", "sensitivity_label": "restricted"},
    )
    assert upload_res.status_code == 503
    assert "Key service is locked" in upload_res.json()["detail"]


def test_shamir_api_unlock_authorization_and_validation(shamir_test_context) -> None:
    """Requirement: Require admin authorization, reject insufficient/duplicate shares, unlock cleanly."""
    client, service, users = shamir_test_context
    app = client.app

    # Pre-generate a 2-of-3 share set for testing
    secret = os.urandom(32)
    shares = SplitKeyService.generate_shares(secret.hex(), total=3, threshold=2)

    # 1. Non-admin cannot unlock (403 Forbidden)
    app.dependency_overrides[get_current_user] = lambda: users["uploader"]
    res_forbidden = client.post(
        "/keys/shamir/unlock",
        json={"shares": [shares[0], shares[1]]},
    )
    assert res_forbidden.status_code == 403

    # 2. Admin with insufficient shares (< 2) returns 400 Bad Request
    app.dependency_overrides[get_current_user] = lambda: users["admin"]
    res_insufficient = client.post(
        "/keys/shamir/unlock",
        json={"shares": [shares[0]]},
    )
    assert res_insufficient.status_code == 400
    assert "requires at least 2 shares" in res_insufficient.json()["detail"]

    # 3. Admin with duplicate shares returns 400 Bad Request
    res_duplicate = client.post(
        "/keys/shamir/unlock",
        json={"shares": [shares[0], shares[0]]},
    )
    assert res_duplicate.status_code == 400
    assert "Duplicate share" in res_duplicate.json()["detail"]

    # 4. Admin with valid 2 shares unlocks successfully
    res_ok = client.post(
        "/keys/shamir/unlock",
        json={"shares": [shares[0], shares[1]]},
    )
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["unlocked"] is True
    assert data["version"] == 1
    # Ensure no raw secret key in response
    assert "secret" not in data
    assert "kek" not in data
    assert service.is_unlocked() is True


def test_shamir_api_full_workflow_unlock_upload_rotate_lock(shamir_test_context) -> None:
    """Full end-to-end API test: init/unlock -> upload envelope -> rotate key -> provision new shares -> lock."""
    client, service, users = shamir_test_context
    app = client.app
    admin = users["admin"]
    uploader = users["uploader"]

    # 1. Admin initializes fresh Shamir KEK via API
    app.dependency_overrides[get_current_user] = lambda: admin
    init_res = client.post("/keys/shamir/init")
    assert init_res.status_code == 200
    init_data = init_res.json()
    assert init_data["version"] == 1
    assert init_data["threshold"] == 2
    assert init_data["total_shares"] == 3
    assert len(init_data["shares"]) == 3
    assert service.is_unlocked() is True

    # 2. Uploader uploads an envelope under v1
    app.dependency_overrides[get_current_user] = lambda: uploader
    dummy_file = io.BytesIO(_make_test_png())
    upload_res = client.post(
        "/envelopes",
        files={"file": ("test.png", dummy_file, "image/png")},
        data={"dataset_id": "cifar10", "sensitivity_label": "restricted"},
    )
    assert upload_res.status_code == 201
    _env_id = upload_res.json()["envelope_id"]
    assert _env_id is not None

    # 3. Admin rotates KEK
    app.dependency_overrides[get_current_user] = lambda: admin
    rotate_res = client.post("/keys/rotate")
    assert rotate_res.status_code == 200
    rot_data = rotate_res.json()
    assert rot_data["old_kek_version"] == 1
    assert rot_data["new_kek_version"] == 2
    assert "rewrapped" in rot_data["envelopes_rewrapped"].lower()
    # New Shamir shares returned for custodians
    assert "provisioned_shares" in rot_data
    assert len(rot_data["provisioned_shares"]) == 3

    # 4. Lock Shamir service
    lock_res = client.post("/keys/shamir/lock")
    assert lock_res.status_code == 200
    assert lock_res.json()["locked"] is True
    assert service.is_unlocked() is False

    # 5. When locked, upload is blocked (503)
    app.dependency_overrides[get_current_user] = lambda: uploader
    dummy_file_2 = io.BytesIO(_make_test_png())
    upload_blocked = client.post(
        "/envelopes",
        files={"file": ("test2.png", dummy_file_2, "image/png")},
        data={"dataset_id": "cifar10", "sensitivity_label": "restricted"},
    )
    assert upload_blocked.status_code == 503
