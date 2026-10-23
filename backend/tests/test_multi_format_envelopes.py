"""
Automated Verification Tests for Multi-Format Envelope Ingestion & Retrieval.

Tests support for:
  - Images: PNG, JPG/JPEG, WebP
  - Documents: PDF, DOCX, XLSX
  - Text & Data: TXT, CSV, JSON

Verifies:
  1. Frontend/Backend validation allowing multi-format files
  2. Byte-for-byte fidelity preservation after AES-256-GCM encryption & decryption
  3. Proper MIME type and metadata tracking
  4. End-to-end API upload and access request retrieval flows
"""

from __future__ import annotations

import base64
import io
import uuid
from collections.abc import AsyncGenerator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.adapters.key_service import EnvVarKeyService
from app.adapters.storage import LocalFileAdapter
from app.api.auth import get_current_user
from app.api.envelopes import get_key_service, get_storage_adapter
from app.db.session import CASBase, get_db
from app.main import create_app
from app.models.models import CASDataEnvelope, CASUser
from app.services.envelope import (
    ingest_record,
    minimize_data,
    retrieve_and_decrypt,
    validate_upload,
)
from app.services.identity_service import hash_password


def create_test_image(fmt: str = "PNG") -> bytes:
    """Generate minimal valid image bytes."""
    img = Image.new("RGB", (32, 32), color=(100, 150, 200))
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Unit Tests: validate_upload
# ---------------------------------------------------------------------------


def test_validate_upload_all_supported_formats() -> None:
    # 1. Images
    png_bytes = create_test_image("PNG")
    res_png = validate_upload("chart.png", png_bytes)
    assert res_png.is_valid is True
    assert res_png.content_type == "image/png"
    assert res_png.file_size_bytes == len(png_bytes)

    jpg_bytes = create_test_image("JPEG")
    res_jpg = validate_upload("photo.jpg", jpg_bytes)
    assert res_jpg.is_valid is True
    assert res_jpg.content_type == "image/jpeg"

    # 2. PDF Document
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    res_pdf = validate_upload("paper.pdf", pdf_bytes)
    assert res_pdf.is_valid is True
    assert res_pdf.content_type == "application/pdf"
    assert res_pdf.file_size_bytes == len(pdf_bytes)

    # 3. Plain Text
    txt_bytes = b"CAS-SE: Cryptographic Access & Reference Architecture test data."
    res_txt = validate_upload("notes.txt", txt_bytes)
    assert res_txt.is_valid is True
    assert res_txt.content_type == "text/plain"

    # 4. CSV Spreadsheet
    csv_bytes = b"id,subject,score\n1,subject-01,98.5\n2,subject-02,87.0\n"
    res_csv = validate_upload("dataset.csv", csv_bytes)
    assert res_csv.is_valid is True
    assert res_csv.content_type == "text/csv"

    # 5. JSON Structured Data
    json_bytes = b'{"version": 1, "dataset": "mnist", "features": [0.1, 0.2, 0.3]}'
    res_json = validate_upload("metadata.json", json_bytes)
    assert res_json.is_valid is True
    assert res_json.content_type == "application/json"

    # 6. DOCX Binary Document
    docx_bytes = b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00MockDOCXBinaryHeaderAndBodyContent"
    res_docx = validate_upload("specification.docx", docx_bytes)
    assert res_docx.is_valid is True
    assert res_docx.content_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

    # 7. XLSX Binary Spreadsheet
    xlsx_bytes = b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00MockXLSXBinaryHeaderAndBodyContent"
    res_xlsx = validate_upload("metrics.xlsx", xlsx_bytes)
    assert res_xlsx.is_valid is True
    assert res_xlsx.content_type == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def test_validate_upload_rejections() -> None:
    # Disallowed binary extension
    res_exe = validate_upload("malware.exe", b"MZ\x90\x00\x03")
    assert res_exe.is_valid is False
    assert "not allowed" in (res_exe.error or "")

    res_sh = validate_upload("script.sh", b"#!/bin/bash\nrm -rf /")
    assert res_sh.is_valid is False
    assert "not allowed" in (res_sh.error or "")

    # Empty file
    res_empty = validate_upload("empty.txt", b"")
    assert res_empty.is_valid is False
    assert "cannot be empty" in (res_empty.error or "").lower()

    # Corrupt image masquerading as PNG
    res_corrupt_png = validate_upload("fake.png", b"Not A Valid PNG File")
    assert res_corrupt_png.is_valid is False
    assert "not a valid image" in (res_corrupt_png.error or "").lower()

    # Exceeding size limit
    res_oversize = validate_upload("huge.txt", b"A" * 1024, max_bytes=512)
    assert res_oversize.is_valid is False
    assert "exceeds limit" in (res_oversize.error or "").lower()


# ---------------------------------------------------------------------------
# Unit Tests: Cryptographic Preservation and Decryption Round-Trip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("filename", "payload"),
    [
        ("test.png", create_test_image("PNG")),
        ("test.jpg", create_test_image("JPEG")),
        ("manual.pdf", b"%PDF-1.4\n%Binary stream data \x00\x01\x02\xff\xfe\n%%EOF"),
        ("readme.txt", b"Plaintext bytes preserved exactly through AES-GCM encryption."),
        ("data.csv", b"colA,colB,colC\n1,2,3\n4,5,6\n"),
        ("manifest.json", b'{"key": "value", "numbers": [10, 20, 30]}'),
        ("archive.docx", b"PK\x03\x04MockBinaryWordDocumentStream\x00\x1f\x8b\xff"),
        ("table.xlsx", b"PK\x03\x04MockBinaryExcelWorkbookStream\xaa\xbb\xcc\xdd"),
    ],
)
def test_crypto_round_trip_preserves_exact_bytes(
    tmp_path: pytest.TempPathFactory,
    filename: str,
    payload: bytes,
) -> None:
    storage = LocalFileAdapter(str(tmp_path))
    kek = b"k" * 32
    kek_version = 1
    envelope_id = uuid.uuid4()
    object_key = f"envelopes/{envelope_id.hex}"

    # Ingest record
    result = ingest_record(
        plaintext=payload,
        envelope_id=envelope_id,
        policy_id=None,
        sensitivity_label="restricted",
        kek=kek,
        kek_version=kek_version,
        object_key=object_key,
        storage_adapter=storage,
    )

    # Object storage holds ciphertext, never plaintext
    stored_ciphertext = storage.get_object(object_key)
    assert stored_ciphertext != payload
    assert payload not in stored_ciphertext

    # Reconstruct envelope model instance
    envelope = CASDataEnvelope(
        id=result.envelope_id,
        object_uri=result.object_uri,
        nonce_hex=result.nonce_hex,
        wrapped_dek=result.wrapped_dek_b64,
        kek_version=result.kek_version,
        sensitivity_label=result.sensitivity_label,
        encryption_version=result.encryption_version,
        policy_id=None,
    )

    decrypted = retrieve_and_decrypt(envelope, kek, storage)

    # Byte-for-byte exact equality
    assert decrypted == payload
    assert len(decrypted) == len(payload)


def test_minimize_data_supports_non_image_documents() -> None:
    pdf_bytes = b"%PDF-1.4 binary content"
    txt_bytes = b"Sensitive clinical report"

    # raw_image view returns exact raw payload for any format
    assert minimize_data(pdf_bytes, "raw_image") == pdf_bytes
    assert minimize_data(txt_bytes, "raw_image") == txt_bytes

    # metadata_only view returns empty payload
    assert minimize_data(pdf_bytes, "metadata_only") == b""
    assert minimize_data(txt_bytes, "metadata_only") == b""

    # masked_image view gracefully redacts non-images without crashing
    masked_pdf = minimize_data(pdf_bytes, "masked_image")
    assert b"REDACTED" in masked_pdf

    masked_txt = minimize_data(txt_bytes, "masked_image")
    assert b"REDACTED" in masked_txt


# ---------------------------------------------------------------------------
# API Integration Tests: Upload & Retrieval via TestClient
# ---------------------------------------------------------------------------


@pytest.fixture
async def multi_format_test_env(tmp_path: pytest.TempPathFactory) -> AsyncGenerator[dict[str, Any]]:
    test_db_url = "sqlite+aiosqlite:///:memory:"
    test_engine = create_async_engine(test_db_url, echo=False)
    test_session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with test_engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.create_all)

    admin_user = CASUser(
        id=uuid.uuid4(),
        username="admin_mf",
        email="admin_mf@test.org",
        hashed_password=hash_password("Pass123!"),
        role="admin",
        is_active=True,
    )

    async with test_session_factory() as session:
        session.add(admin_user)
        await session.commit()

    storage = LocalFileAdapter(str(tmp_path))
    key_service = EnvVarKeyService()
    if not key_service._versions:
        key_service._versions[1] = b"\x01" * 32
        key_service._current_version = 1

    app = create_app()

    async def override_get_db() -> AsyncGenerator[AsyncSession]:
        async with test_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_storage_adapter] = lambda: storage
    app.dependency_overrides[get_key_service] = lambda: key_service
    app.dependency_overrides[get_current_user] = lambda: admin_user

    client = TestClient(app)

    yield {
        "client": client,
        "admin": admin_user,
    }

    await test_engine.dispose()


@pytest.mark.asyncio
async def test_api_upload_and_access_all_formats(multi_format_test_env: dict[str, Any]) -> None:
    client: TestClient = multi_format_test_env["client"]

    test_files = [
        ("chart.png", create_test_image("PNG"), "image/png"),
        ("photo.jpg", create_test_image("JPEG"), "image/jpeg"),
        ("report.pdf", b"%PDF-1.4\n1 0 obj << /Title (CAS-SE Test) >> endobj\n%%EOF", "application/pdf"),
        ("notes.txt", b"Confidential researcher experiment observations.", "text/plain"),
        ("sample.docx", b"PK\x03\x04\x14\x00\x00\x00\x08\x00MockBinaryDocxPayloadData", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        ("ledger.xlsx", b"PK\x03\x04\x14\x00\x00\x00\x08\x00MockBinaryXlsxPayloadData", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        ("config.json", b'{"organization": "CAS-SE", "encrypted": true}', "application/json"),
    ]

    for filename, raw_bytes, expected_content_type in test_files:
        # 1. Upload envelope
        upload_res = client.post(
            "/envelopes",
            data={
                "dataset_id": "test_dataset",
                "subject_id": "subject_001",
                "sensitivity_label": "restricted",
            },
            files={"file": (filename, raw_bytes, expected_content_type)},
        )
        assert upload_res.status_code == 201, f"Upload failed for {filename}: {upload_res.text}"
        envelope_id = upload_res.json()["envelope_id"]

        # 2. Verify metadata in /envelopes/{id}
        meta_res = client.get(f"/envelopes/{envelope_id}")
        assert meta_res.status_code == 200
        assert meta_res.json()["content_type"] == expected_content_type
        assert meta_res.json()["file_size_bytes"] == len(raw_bytes)

        # 3. Access request (raw_image allowed view gives full decrypted payload)
        access_res = client.post(
            "/access-request",
            json={
                "envelope_id": envelope_id,
                "purpose": "administrative_review",
                "requested_view": "raw_image",
            },
        )
        assert access_res.status_code == 200, f"Access request failed for {filename}: {access_res.text}"
        access_data = access_res.json()
        assert access_data["decision"] in ("allow", "raw_image")
        assert access_data["content_type"] == expected_content_type

        # 4. Assert recovered payload is byte-for-byte identical to the uploaded file
        recovered_bytes = base64.b64decode(access_data["data_b64"])
        assert recovered_bytes == raw_bytes, f"Decrypted payload mismatch for {filename}!"
