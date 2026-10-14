"""Tests for CAS-SE Envelope Ingestion & API (Phase 3)."""

from __future__ import annotations

import io
import uuid
from collections.abc import AsyncGenerator

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.adapters.key_service import EnvVarKeyService
from app.adapters.storage import LocalFileAdapter
from app.api.auth import get_current_user
from app.api.envelopes import get_key_service, get_storage_adapter
from app.db.session import CASBase, get_db
from app.main import create_app
from app.models.models import CASAccessAudit, CASDataEnvelope, CASProtectedIndex, CASUser
from app.services.envelope import (
    ingest_record,
    minimize_data,
    retrieve_and_decrypt,
    validate_upload,
)
from app.services.identity_service import hash_password


def create_test_image_bytes(format: str = "PNG", size: tuple[int, int] = (64, 64)) -> bytes:
    """Helper to generate valid image bytes with visible pattern in memory."""
    from PIL import ImageDraw

    img = Image.new("RGB", size, color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.rectangle([10, 10, 40, 40], fill=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format=format)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Unit Tests: Upload Validation
# ---------------------------------------------------------------------------


def test_validate_upload_valid_images() -> None:
    png_bytes = create_test_image_bytes("PNG")
    val_png = validate_upload("sample.png", png_bytes)
    assert val_png.is_valid is True
    assert val_png.content_type == "image/png"
    assert val_png.file_size_bytes == len(png_bytes)

    jpeg_bytes = create_test_image_bytes("JPEG")
    val_jpeg = validate_upload("sample.jpg", jpeg_bytes)
    assert val_jpeg.is_valid is True
    assert val_jpeg.content_type == "image/jpeg"


def test_validate_upload_disallowed_extension() -> None:
    val = validate_upload("malicious.exe", b"not_an_image")
    assert val.is_valid is False
    assert "not allowed" in (val.error or "")


def test_validate_upload_corrupt_data() -> None:
    val = validate_upload("fake.png", b"not a real image payload")
    assert val.is_valid is False
    assert "not a valid image" in (val.error or "")


def test_validate_upload_exceeds_size_limit() -> None:
    data = b"x" * 1024
    val = validate_upload("sample.png", data, max_bytes=512)
    assert val.is_valid is False
    assert "exceeds limit" in (val.error or "")


# ---------------------------------------------------------------------------
# Unit Tests: Ingest and Retrieve / Decrypt
# ---------------------------------------------------------------------------


def test_ingest_and_retrieve_decrypt_round_trip(tmp_path: pytest.TempPathFactory) -> None:
    storage = LocalFileAdapter(str(tmp_path))
    kek = b"0" * 32
    kek_version = 1
    envelope_id = uuid.uuid4()
    object_key = f"envelopes/{envelope_id.hex}"
    plaintext = create_test_image_bytes("PNG")

    # Ingest record
    result = ingest_record(
        plaintext=plaintext,
        envelope_id=envelope_id,
        policy_id=None,
        sensitivity_label="restricted",
        kek=kek,
        kek_version=kek_version,
        object_key=object_key,
        storage_adapter=storage,
    )

    assert result.envelope_id == envelope_id
    assert result.object_uri == object_key
    assert len(result.nonce_hex) == 24  # 12 bytes = 24 hex chars
    assert result.wrapped_dek_b64 is not None

    # Verify object storage contains ciphertext, not plaintext
    stored_ciphertext = storage.get_object(object_key)
    assert stored_ciphertext != plaintext
    assert plaintext not in stored_ciphertext

    # Mock ORM object
    class DummyEnvelope:
        def __init__(self, res: type[ingest_record]):
            self.id = res.envelope_id
            self.object_uri = res.object_uri
            self.nonce_hex = res.nonce_hex
            self.wrapped_dek = res.wrapped_dek_b64
            self.kek_version = res.kek_version
            self.sensitivity_label = res.sensitivity_label
            self.encryption_version = res.encryption_version
            self.policy_id = None

    orm_envelope = DummyEnvelope(result)
    decrypted = retrieve_and_decrypt(orm_envelope, kek, storage)
    assert decrypted == plaintext


def test_retrieve_and_decrypt_tampered_ciphertext(tmp_path: pytest.TempPathFactory) -> None:
    storage = LocalFileAdapter(str(tmp_path))
    kek = b"0" * 32
    envelope_id = uuid.uuid4()
    object_key = f"envelopes/{envelope_id.hex}"
    plaintext = b"sensitive bytes"

    result = ingest_record(
        plaintext=plaintext,
        envelope_id=envelope_id,
        policy_id=None,
        sensitivity_label="restricted",
        kek=kek,
        kek_version=1,
        object_key=object_key,
        storage_adapter=storage,
    )

    # Tamper with stored ciphertext in storage
    tampered = bytearray(storage.get_object(object_key))
    tampered[0] ^= 0x01
    storage.put_object(object_key, bytes(tampered))

    class DummyEnvelope:
        def __init__(self, res: type[ingest_record]):
            self.id = res.envelope_id
            self.object_uri = res.object_uri
            self.nonce_hex = res.nonce_hex
            self.wrapped_dek = res.wrapped_dek_b64
            self.kek_version = res.kek_version
            self.sensitivity_label = res.sensitivity_label
            self.encryption_version = res.encryption_version
            self.policy_id = None

    with pytest.raises(InvalidTag):
        retrieve_and_decrypt(DummyEnvelope(result), kek, storage)


# ---------------------------------------------------------------------------
# Unit Tests: Data Minimization
# ---------------------------------------------------------------------------


def test_minimize_data_views() -> None:
    raw_img = create_test_image_bytes("PNG")

    # raw_image view
    raw_out = minimize_data(raw_img, "raw_image")
    assert raw_out == raw_img

    # metadata_only view
    meta_out = minimize_data(raw_img, "metadata_only")
    assert meta_out == b""

    # feature_only view
    feat_out = minimize_data(raw_img, "feature_only")
    assert feat_out == b""

    # masked_image view
    masked_out = minimize_data(raw_img, "masked_image")
    assert isinstance(masked_out, bytes)
    assert len(masked_out) > 0
    assert masked_out != raw_img

    # Invalid view
    with pytest.raises(ValueError, match="Unknown allowed_view"):
        minimize_data(raw_img, "unauthorized_view")


# ---------------------------------------------------------------------------
# Integration Tests: FastAPI /envelopes Endpoints with TestClient
# ---------------------------------------------------------------------------


@pytest.fixture
async def envelope_test_context(
    tmp_path: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[tuple[TestClient, async_sessionmaker[AsyncSession], LocalFileAdapter]]:
    """Sets up an in-memory test DB, temp storage, seeded users, and TestClient."""
    import base64

    monkeypatch.setenv("CAS_KEK_V1", base64.b64encode(b"k" * 32).decode("ascii"))
    monkeypatch.setenv("CAS_KEK_CURRENT_VERSION", "1")

    test_db_url = "sqlite+aiosqlite:///:memory:"
    test_engine = create_async_engine(test_db_url, echo=False)
    test_session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with test_engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.create_all)

    # Seed test users
    admin_user = CASUser(
        id=uuid.uuid4(),
        username="admin_test",
        email="admin@test.org",
        hashed_password=hash_password("AdminPass123!"),
        role="admin",
        is_active=True,
    )
    uploader_user = CASUser(
        id=uuid.uuid4(),
        username="uploader_test",
        email="uploader@test.org",
        hashed_password=hash_password("UploaderPass123!"),
        role="uploader",
        is_active=True,
    )
    other_uploader = CASUser(
        id=uuid.uuid4(),
        username="other_uploader",
        email="other@test.org",
        hashed_password=hash_password("UploaderPass123!"),
        role="uploader",
        is_active=True,
    )
    trainer_user = CASUser(
        id=uuid.uuid4(),
        username="trainer_test",
        email="trainer@test.org",
        hashed_password=hash_password("TrainerPass123!"),
        role="trainer",
        is_active=True,
    )

    async with test_session_factory() as session:
        session.add_all([admin_user, uploader_user, other_uploader, trainer_user])
        await session.commit()

    storage_adapter = LocalFileAdapter(str(tmp_path / "storage"))
    key_service = EnvVarKeyService()

    app = create_app()

    async def override_get_db() -> AsyncGenerator[AsyncSession]:
        async with test_session_factory() as session:
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

    # Attach users for test access
    client.admin_user = admin_user  # type: ignore[attr-defined]
    client.uploader_user = uploader_user  # type: ignore[attr-defined]
    client.other_uploader = other_uploader  # type: ignore[attr-defined]
    client.trainer_user = trainer_user  # type: ignore[attr-defined]

    yield client, test_session_factory, storage_adapter

    app.dependency_overrides.clear()
    await test_engine.dispose()


@pytest.mark.asyncio
async def test_envelope_upload_unauthorized_role_rejected(envelope_test_context) -> None:
    client, _session_factory, _ = envelope_test_context
    app = client.app

    # Authenticate as trainer (trainers cannot upload)
    app.dependency_overrides[get_current_user] = lambda: client.trainer_user

    img_data = create_test_image_bytes("PNG")
    response = client.post(
        "/envelopes",
        files={"file": ("img.png", img_data, "image/png")},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_envelope_upload_validation_failure_audited(envelope_test_context) -> None:
    client, session_factory, _ = envelope_test_context
    app = client.app

    app.dependency_overrides[get_current_user] = lambda: client.uploader_user

    # Upload invalid file (text file with disallowed extension)
    response = client.post(
        "/envelopes",
        files={"file": ("script.sh", b"echo hello", "text/x-sh")},
    )
    assert response.status_code == 422

    # Verify audit event recorded denial
    async with session_factory() as session:
        from sqlalchemy import select

        audit_res = await session.execute(
            select(CASAccessAudit).where(CASAccessAudit.event_type == "upload")
        )
        audit_events = audit_res.scalars().all()
        assert len(audit_events) == 1
        assert audit_events[0].decision == "deny"
        assert audit_events[0].actor_id == client.uploader_user.id
        assert "not allowed" in (audit_events[0].reason or "")


@pytest.mark.asyncio
async def test_envelope_upload_and_policy_filtered_listing(envelope_test_context) -> None:
    client, session_factory, storage = envelope_test_context
    app = client.app

    # 1. Upload as uploader_user
    app.dependency_overrides[get_current_user] = lambda: client.uploader_user
    img_data = create_test_image_bytes("JPEG")
    res = client.post(
        "/envelopes",
        files={"file": ("scan.jpg", img_data, "image/jpeg")},
        data={"dataset_id": "chest-xray-01", "class_label": "normal"},
    )
    assert res.status_code == 201
    env1_id = res.json()["envelope_id"]

    # 2. Upload as other_uploader
    app.dependency_overrides[get_current_user] = lambda: client.other_uploader
    res2 = client.post(
        "/envelopes",
        files={"file": ("scan2.jpg", img_data, "image/jpeg")},
        data={"dataset_id": "chest-xray-02", "class_label": "pneumonia"},
    )
    assert res2.status_code == 201
    env2_id = res2.json()["envelope_id"]

    # 3. Verify Database and Storage state
    async with session_factory() as session:
        from sqlalchemy import select

        # Verify envelope 1 in DB
        res_env1 = await session.execute(
            select(CASDataEnvelope).where(CASDataEnvelope.id == uuid.UUID(env1_id))
        )
        envelope_record = res_env1.scalar_one()
        assert envelope_record.uploaded_by == client.uploader_user.id
        assert envelope_record.dataset_id is None
        assert envelope_record.dataset_scope_token is not None
        assert envelope_record.file_size_bytes == len(img_data)

        # Verify protected indexes created
        res_idx = await session.execute(
            select(CASProtectedIndex).where(CASProtectedIndex.envelope_id == uuid.UUID(env1_id))
        )
        indexes = res_idx.scalars().all()
        assert len(indexes) == 2  # dataset_id and class_label
        indexed_field_names = {idx.field_name for idx in indexes}
        assert indexed_field_names == {"dataset_id", "class_label"}

        # Verify ciphertext in object storage is NOT plaintext
        stored_blob = storage.get_object(envelope_record.object_uri)
        assert stored_blob != img_data
        assert img_data not in stored_blob

        # Verify audit event for success
        audit_res = await session.execute(
            select(CASAccessAudit).where(
                CASAccessAudit.envelope_id == uuid.UUID(env1_id),
                CASAccessAudit.event_type == "upload",
            )
        )
        audit_record = audit_res.scalar_one()
        assert audit_record.decision == "allow"
        assert audit_record.actor_id == client.uploader_user.id

    # 4. List envelopes as uploader_user -- should ONLY see env1
    app.dependency_overrides[get_current_user] = lambda: client.uploader_user
    list_uploader = client.get("/envelopes")
    assert list_uploader.status_code == 200
    uploader_env_ids = [item["envelope_id"] for item in list_uploader.json()]
    assert env1_id in uploader_env_ids
    assert env2_id not in uploader_env_ids

    # 5. List envelopes as admin -- should see BOTH env1 and env2
    app.dependency_overrides[get_current_user] = lambda: client.admin_user
    list_admin = client.get("/envelopes")
    assert list_admin.status_code == 200
    admin_env_ids = [item["envelope_id"] for item in list_admin.json()]
    assert env1_id in admin_env_ids
    assert env2_id in admin_env_ids

    # 6. Single envelope lookup permissions:
    # Uploader looking up own envelope -> 200
    app.dependency_overrides[get_current_user] = lambda: client.uploader_user
    get_own = client.get(f"/envelopes/{env1_id}")
    assert get_own.status_code == 200
    assert get_own.json()["envelope_id"] == env1_id
    assert "wrapped_dek" not in get_own.json()  # Secrets never returned!
    assert "nonce" not in get_own.json()

    # Uploader looking up other user's envelope -> 403 Forbidden
    get_other = client.get(f"/envelopes/{env2_id}")
    assert get_other.status_code == 403

    # Admin looking up any envelope -> 200
    app.dependency_overrides[get_current_user] = lambda: client.admin_user
    get_by_admin = client.get(f"/envelopes/{env2_id}")
    assert get_by_admin.status_code == 200
