"""
CAS-SE Envelope Service -- Phase 3

Encrypted ingestion pipeline:
  validate -> generate DEK -> encrypt -> store ciphertext -> persist metadata -> index

Data minimization (used on access, Phase 4):
  raw_image | feature_only | masked_image | metadata_only

Security invariants:
  - RDBMS stores ONLY metadata -- never raw bytes or decrypted content.
  - Object storage stores ONLY ciphertext blobs.
  - Every upload attempt is audited (success and failure).
  - AAD binds ciphertext to envelope_id / policy_id / sensitivity_label.
  - Object keys are randomised -- never derived from original filenames.
"""

from __future__ import annotations

import io
import uuid
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, UnidentifiedImageError

from app.adapters.key_service import KeyServiceAdapter
from app.adapters.storage import StorageAdapter
from app.core.config import get_settings
from app.models.models import CASDataEnvelope
from app.services.crypto import (
    build_aad,
    compute_hmac_token,
    decrypt_payload,
    encrypt_payload,
    generate_dek,
    unwrap_dek,
    wrap_dek,
)

settings = get_settings()


# ---------------------------------------------------------------------------
# Upload validation
# ---------------------------------------------------------------------------

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"}
MAX_BYTES = settings.max_upload_bytes  # 10 MB default


@dataclass
class UploadValidationResult:
    is_valid: bool
    content_type: str
    file_size_bytes: int
    error: str | None = None


def validate_upload(
    filename: str, data: bytes, max_bytes: int = MAX_BYTES
) -> UploadValidationResult:
    """
    Validate an uploaded file before encryption.

    Checks:
      1. File size ≤ max_bytes
      2. Extension is in the allowlist
      3. Data is decodable as an image (PIL verification)

    :returns: UploadValidationResult with is_valid=True on success.
    """
    if len(data) > max_bytes:
        return UploadValidationResult(
            is_valid=False,
            content_type="",
            file_size_bytes=len(data),
            error=f"File size {len(data)} bytes exceeds limit of {max_bytes} bytes",
        )

    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return UploadValidationResult(
            is_valid=False,
            content_type="",
            file_size_bytes=len(data),
            error=f"Extension {ext!r} is not allowed. Permitted: {sorted(ALLOWED_EXTENSIONS)}",
        )

    # Attempt image decode (detects corrupt or non-image files)
    try:
        img = Image.open(io.BytesIO(data))
        img.verify()
        content_type = Image.MIME.get(img.format or "", "application/octet-stream")
    except (UnidentifiedImageError, Exception) as e:
        return UploadValidationResult(
            is_valid=False,
            content_type="",
            file_size_bytes=len(data),
            error=f"File is not a valid image: {e}",
        )

    return UploadValidationResult(
        is_valid=True,
        content_type=content_type,
        file_size_bytes=len(data),
    )


# ---------------------------------------------------------------------------
# Encrypted ingestion
# ---------------------------------------------------------------------------


@dataclass
class IngestionResult:
    """Result of a successful encrypted ingestion."""

    envelope_id: uuid.UUID
    object_uri: str
    nonce_hex: str
    wrapped_dek_b64: str
    kek_version: int
    ciphertext_sha256: str
    sensitivity_label: str
    encryption_version: int = 1


def ingest_record(
    plaintext: bytes,
    envelope_id: uuid.UUID,
    policy_id: str | None,
    sensitivity_label: str,
    kek: bytes,
    kek_version: int,
    object_key: str,
    storage_adapter: StorageAdapter,
    encryption_version: int = 1,
    key_service: KeyServiceAdapter | None = None,
) -> IngestionResult:
    """
    Encrypt and store a data record.

    Steps:
      1. Generate fresh random DEK.
      2. Build AAD from envelope metadata.
      3. Encrypt plaintext with AES-256-GCM.
      4. Store ciphertext in object storage.
      5. Wrap DEK with KEK.
      6. Return metadata for database persistence.

    No raw data is written to the RDBMS -- only ciphertext is stored in object storage.
    """
    # 1. Fresh DEK
    dek = generate_dek()

    # 2. AAD
    aad = build_aad(
        envelope_id=str(envelope_id),
        policy_id=policy_id,
        sensitivity_label=sensitivity_label,
        encryption_version=encryption_version,
    )

    # 3. Encrypt
    encrypted = encrypt_payload(plaintext, dek, aad)

    # 4. Store ciphertext in object storage
    storage_adapter.put_object(object_key, encrypted.ciphertext)

    # 5. Wrap DEK
    if key_service is not None:
        wrapped_dek_b64, wrapped_version = key_service.wrap_dek(dek)
    else:
        wrapped = wrap_dek(dek, kek, kek_version)
        wrapped_dek_b64, wrapped_version = wrapped.wrapped_dek_b64, wrapped.kek_version

    return IngestionResult(
        envelope_id=envelope_id,
        object_uri=object_key,
        nonce_hex=encrypted.nonce.hex(),
        wrapped_dek_b64=wrapped_dek_b64,
        kek_version=wrapped_version,
        ciphertext_sha256=encrypted.ciphertext_sha256,
        sensitivity_label=sensitivity_label,
        encryption_version=encryption_version,
    )


# ---------------------------------------------------------------------------
# Decryption (used by access service in Phase 4)
# ---------------------------------------------------------------------------


def retrieve_and_decrypt(
    envelope: CASDataEnvelope,
    kek: bytes | KeyServiceAdapter,
    storage_adapter: StorageAdapter,
) -> bytes:
    """
    Retrieve ciphertext from object storage and decrypt with the envelope's DEK.

    :raises KeyError: If ciphertext object not found in storage.
    :raises cryptography.exceptions.InvalidTag: If authentication fails.
    """
    ciphertext = storage_adapter.get_object(envelope.object_uri)

    aad = build_aad(
        envelope_id=str(envelope.id),
        policy_id=str(envelope.policy_id) if envelope.policy_id else None,
        sensitivity_label=envelope.sensitivity_label,
        encryption_version=envelope.encryption_version,
    )

    if isinstance(kek, bytes):
        dek = unwrap_dek(envelope.wrapped_dek, kek)
    else:
        dek = kek.unwrap_dek(envelope.wrapped_dek, envelope.kek_version)
    nonce = bytes.fromhex(envelope.nonce_hex)
    return decrypt_payload(ciphertext, nonce, dek, aad)


# ---------------------------------------------------------------------------
# Data minimization (Phase 4 output views)
# ---------------------------------------------------------------------------


def minimize_data(
    plaintext: bytes,
    allowed_view: str,
) -> bytes:
    """
    Return a minimized data representation based on the policy decision.

    :param plaintext: Decrypted raw image bytes.
    :param allowed_view: One of metadata_only | masked_image | feature_only | raw_image.
    :returns: Minimized data appropriate for the allowed view.
    """
    if allowed_view == "raw_image":
        return plaintext

    if allowed_view == "metadata_only":
        # Return no image content -- metadata is returned separately via envelope model
        return b""

    if allowed_view == "masked_image":
        return _blur_image(plaintext)

    if allowed_view == "feature_only":
        # Feature extraction is done asynchronously by the worker (Phase 5)
        # Here we return a placeholder indicating the worker should be queried
        return b""

    raise ValueError(f"Unknown allowed_view: {allowed_view!r}")


def _blur_image(image_bytes: bytes, blur_radius: int = 20) -> bytes:
    """Apply heavy Gaussian blur to produce a masked/de-identified image."""
    from PIL import ImageFilter

    img = Image.open(io.BytesIO(image_bytes))
    blurred = img.filter(ImageFilter.GaussianBlur(radius=blur_radius))
    out = io.BytesIO()
    blurred.save(out, format=img.format or "PNG")
    return out.getvalue()


# ---------------------------------------------------------------------------
# HMAC index helpers
# ---------------------------------------------------------------------------

INDEXED_FIELDS = {"dataset_id", "subject_id", "class_label"}


def build_protected_indexes(
    field_values: dict[str, str],
    index_key: bytes,
    token_version: int = 1,
) -> dict[str, bytes]:
    """
    Compute HMAC tokens for approved equality-search fields.

    Only `INDEXED_FIELDS` are indexed -- no arbitrary fields accepted.

    :returns: dict of field_name -> 32-byte HMAC token.
    """
    tokens: dict[str, bytes] = {}
    for field, value in field_values.items():
        if field not in INDEXED_FIELDS:
            continue
        tokens[field] = compute_hmac_token(value, index_key)
    return tokens
