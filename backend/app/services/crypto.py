"""
CAS-SE Cryptographic Service

Core cryptographic operations for the envelope encryption scheme.

Design:
  - Each data record encrypted with a fresh random 32-byte DEK (AES-256-GCM).
  - DEK wrapped with the current KEK version (AES-256-GCM wrapping).
  - Nonce: 12 random bytes per encryption operation (never reused).
  - AAD: includes envelope_id, policy_id, sensitivity_label, encryption_version
    to bind ciphertext to its metadata (prevents ciphertext swapping attacks).
  - HMAC-SHA-256 for protected search indexes and audit chain.

No cryptographic algorithms are invented here -- only established primitives
from the `cryptography` library are used.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import unicodedata
from base64 import b64decode, b64encode, urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEK_SIZE_BYTES = 32  # 256-bit DEK
NONCE_SIZE_BYTES = 12  # 96-bit GCM nonce (NIST recommended)
AUTH_TAG_BYTES = 16  # GCM authentication tag (default, enforced by library)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EncryptedPayload:
    """Result of encrypting a plaintext payload with AES-256-GCM."""

    ciphertext: bytes  # ciphertext + GCM auth tag
    nonce: bytes  # 12-byte random nonce
    ciphertext_sha256: str  # hex-encoded SHA-256 of ciphertext (integrity reference)


@dataclass(frozen=True)
class WrappedDEK:
    """Result of wrapping a DEK with the KEK."""

    wrapped_dek_b64: str  # base64-encoded wrapped DEK
    kek_version: int


# ---------------------------------------------------------------------------
# DEK generation
# ---------------------------------------------------------------------------


def generate_dek() -> bytes:
    """Generate a fresh cryptographically random 32-byte Data Encryption Key."""
    return os.urandom(DEK_SIZE_BYTES)


# ---------------------------------------------------------------------------
# AAD construction
# ---------------------------------------------------------------------------


def build_aad(
    envelope_id: str,
    policy_id: str | None,
    sensitivity_label: str,
    encryption_version: int,
) -> bytes:
    """
    Build Authenticated Associated Data (AAD) for AES-GCM.

    The AAD binds ciphertext to its envelope metadata. If an attacker swaps
    ciphertext between envelopes, GCM authentication fails on decryption.

    The AAD is a canonical JSON string (sorted keys, no whitespace) encoded
    as UTF-8 bytes.
    """
    aad_dict = {
        "envelope_id": str(envelope_id),
        "policy_id": str(policy_id) if policy_id else "",
        "sensitivity_label": sensitivity_label,
        "encryption_version": encryption_version,
    }
    return json.dumps(aad_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# AES-256-GCM encryption / decryption
# ---------------------------------------------------------------------------


def encrypt_payload(plaintext: bytes, dek: bytes, aad: bytes) -> EncryptedPayload:
    """
    Encrypt `plaintext` with AES-256-GCM using `dek` and `aad`.

    :param plaintext: Raw bytes to encrypt (e.g., image data).
    :param dek: 32-byte Data Encryption Key.
    :param aad: Authenticated Associated Data (must match on decryption).
    :returns: EncryptedPayload containing ciphertext, nonce, and SHA-256 hash.
    :raises ValueError: If dek length is not 32 bytes.
    """
    if len(dek) != DEK_SIZE_BYTES:
        raise ValueError(f"DEK must be {DEK_SIZE_BYTES} bytes; got {len(dek)}")

    nonce = os.urandom(NONCE_SIZE_BYTES)
    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)  # includes GCM auth tag
    ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()

    return EncryptedPayload(
        ciphertext=ciphertext,
        nonce=nonce,
        ciphertext_sha256=ciphertext_hash,
    )


def decrypt_payload(
    ciphertext: bytes,
    nonce: bytes,
    dek: bytes,
    aad: bytes,
) -> bytes:
    """
    Decrypt `ciphertext` with AES-256-GCM using `dek` and `aad`.

    :raises cryptography.exceptions.InvalidTag: If authentication fails
        (ciphertext or AAD was tampered with).
    :raises ValueError: If dek or nonce lengths are incorrect.
    """
    if len(dek) != DEK_SIZE_BYTES:
        raise ValueError(f"DEK must be {DEK_SIZE_BYTES} bytes; got {len(dek)}")
    if len(nonce) != NONCE_SIZE_BYTES:
        raise ValueError(f"Nonce must be {NONCE_SIZE_BYTES} bytes; got {len(nonce)}")

    aesgcm = AESGCM(dek)
    return aesgcm.decrypt(nonce, ciphertext, aad)  # raises InvalidTag on failure


# ---------------------------------------------------------------------------
# DEK wrapping (envelope encryption)
# ---------------------------------------------------------------------------


def wrap_dek(dek: bytes, kek: bytes, kek_version: int) -> WrappedDEK:
    """
    Wrap (encrypt) a DEK with the KEK using AES-256-GCM.

    The DEK nonce is prepended to the wrapped ciphertext:
      stored = base64(nonce || wrapped_dek_ciphertext)

    :param dek: 32-byte raw DEK to protect.
    :param kek: 32-byte Key Encryption Key.
    :param kek_version: Integer version of the KEK.
    :returns: WrappedDEK with base64-encoded wrapped material.
    """
    if len(kek) != DEK_SIZE_BYTES:
        raise ValueError(f"KEK must be {DEK_SIZE_BYTES} bytes; got {len(kek)}")

    nonce = os.urandom(NONCE_SIZE_BYTES)
    aesgcm = AESGCM(kek)
    wrapped = aesgcm.encrypt(nonce, dek, None)
    stored = b64encode(nonce + wrapped).decode("ascii")
    return WrappedDEK(wrapped_dek_b64=stored, kek_version=kek_version)


def unwrap_dek(wrapped_dek_b64: str, kek: bytes) -> bytes:
    """
    Unwrap (decrypt) a DEK using the KEK.

    :raises cryptography.exceptions.InvalidTag: If KEK is wrong or data tampered.
    :raises ValueError: If the stored blob is too short.
    """
    raw = b64decode(wrapped_dek_b64)
    if len(raw) < NONCE_SIZE_BYTES + AUTH_TAG_BYTES:
        raise ValueError("Wrapped DEK blob is too short to be valid")

    nonce = raw[:NONCE_SIZE_BYTES]
    wrapped = raw[NONCE_SIZE_BYTES:]
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(nonce, wrapped, None)


# ---------------------------------------------------------------------------
# HMAC-SHA-256 protected search index tokens
# ---------------------------------------------------------------------------


def normalize_index_value(value: str) -> str:
    """
    Normalize a field value before HMAC token computation.

    Normalization ensures consistent tokens regardless of case or Unicode form:
      - NFC Unicode normalization
      - Strip leading/trailing whitespace
      - Lowercase

    Document this normalization in the integration guide so callers apply
    the same transformation before searching.
    """
    return unicodedata.normalize("NFC", value).strip().lower()


def compute_hmac_token(field_value: str, index_key: bytes) -> bytes:
    """
    Compute an HMAC-SHA-256 protected equality-search token.

    :param field_value: The plaintext field value to tokenise (e.g., dataset_id).
    :param index_key: The 32-byte HMAC index key (from settings.index_hmac_key_bytes).
    :returns: 32-byte HMAC token (stored as BYTEA in the database).

    Known limitation: Equality-pattern leakage -- two records with the same
    field value will have the same token, revealing that their values match.
    This is documented in PRD §19.
    """
    normalized = normalize_index_value(field_value)
    return hmac.new(index_key, normalized.encode("utf-8"), hashlib.sha256).digest()


def encode_scope_token(token: bytes, version: int = 1) -> str:
    """Encode an HMAC scope token without retaining the plaintext identifier."""
    return f"v{version}:{urlsafe_b64encode(token).decode('ascii')}"


def decode_scope_token(value: str) -> bytes:
    """Decode a versioned protected scope token stored in CAS-SE metadata."""
    prefix, separator, encoded = value.partition(":")
    if prefix != "v1" or not separator:
        raise ValueError("Unsupported protected scope token")
    try:
        token = urlsafe_b64decode(encoded.encode("ascii"))
    except Exception as exc:
        raise ValueError("Malformed protected scope token") from exc
    if len(token) != 32:
        raise ValueError("Protected scope token has invalid length")
    return token


# ---------------------------------------------------------------------------
# Audit chain HMAC
# ---------------------------------------------------------------------------


def compute_audit_hmac(
    canonical_fields: dict[str, Any],
    prev_hmac: str | None,
    audit_key: bytes,
) -> str:
    """
    Compute the HMAC for an audit event, chained to the previous event.

    :param canonical_fields: Sorted dict of audit fields (no secrets, no raw data).
    :param prev_hmac: hex-encoded HMAC of the previous audit event (None for first).
    :param audit_key: 32-byte audit integrity key.
    :returns: hex-encoded 32-byte HMAC.
    """
    chain_input = {
        "fields": canonical_fields,
        "prev_event_hmac": prev_hmac or "",
    }
    serialized = json.dumps(chain_input, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(audit_key, serialized, hashlib.sha256).hexdigest()


def verify_audit_chain(
    events: list[dict[str, Any]],
    audit_key: bytes,
) -> tuple[bool, int | None]:
    """
    Verify the integrity of the audit chain.

    :param events: List of audit event dicts, ordered by `occurred_at` ascending.
    :param audit_key: 32-byte audit integrity key.
    :returns: (is_valid, first_broken_index) -- first_broken_index is None if valid.
    """
    prev_hmac: str | None = None
    for i, event in enumerate(events):
        stored_hmac = event.pop("event_hmac", None)
        computed = compute_audit_hmac(event, prev_hmac, audit_key)
        event["event_hmac"] = stored_hmac  # restore
        if not hmac.compare_digest(computed, stored_hmac or ""):
            return False, i
        prev_hmac = stored_hmac
    return True, None


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def generate_token(n_bytes: int = 32) -> str:
    """Generate a URL-safe random token (for refresh tokens, manifests, etc.)."""
    return secrets.token_urlsafe(n_bytes)


def sha256_hex(data: bytes) -> str:
    """Return the hex-encoded SHA-256 digest of `data`."""
    return hashlib.sha256(data).hexdigest()
