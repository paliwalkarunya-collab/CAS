"""Tests for CAS-SE Cryptographic Service (services/crypto.py)."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from app.services.crypto import (
    AUTH_TAG_BYTES,
    DEK_SIZE_BYTES,
    NONCE_SIZE_BYTES,
    build_aad,
    compute_audit_hmac,
    compute_hmac_token,
    decrypt_payload,
    encrypt_payload,
    generate_dek,
    generate_token,
    normalize_index_value,
    sha256_hex,
    unwrap_dek,
    verify_audit_chain,
    wrap_dek,
)


def test_dek_generation() -> None:
    dek1 = generate_dek()
    dek2 = generate_dek()
    assert len(dek1) == DEK_SIZE_BYTES
    assert len(dek2) == DEK_SIZE_BYTES
    assert dek1 != dek2


def test_build_aad_deterministic() -> None:
    aad1 = build_aad("env-1", "pol-1", "restricted", 1)
    aad2 = build_aad("env-1", "pol-1", "restricted", 1)
    assert aad1 == aad2
    assert b"env-1" in aad1
    assert b"restricted" in aad1

    # Swapping fields changes AAD
    aad3 = build_aad("env-2", "pol-1", "restricted", 1)
    assert aad1 != aad3


def test_aes_256_gcm_round_trip() -> None:
    plaintext = b"sensitive raw image or medical record bytes"
    dek = generate_dek()
    aad = build_aad("env-1", None, "restricted", 1)

    encrypted = encrypt_payload(plaintext, dek, aad)
    assert len(encrypted.nonce) == NONCE_SIZE_BYTES
    assert len(encrypted.ciphertext) == len(plaintext) + AUTH_TAG_BYTES
    assert encrypted.ciphertext_sha256 == sha256_hex(encrypted.ciphertext)

    decrypted = decrypt_payload(encrypted.ciphertext, encrypted.nonce, dek, aad)
    assert decrypted == plaintext


def test_ciphertext_tampering_detection() -> None:
    plaintext = b"critical record"
    dek = generate_dek()
    aad = build_aad("env-1", None, "restricted", 1)

    encrypted = encrypt_payload(plaintext, dek, aad)

    # Flip one byte in ciphertext
    corrupted = bytearray(encrypted.ciphertext)
    corrupted[0] ^= 0x01

    with pytest.raises(InvalidTag):
        decrypt_payload(bytes(corrupted), encrypted.nonce, dek, aad)


def test_aad_swapping_tampering_detection() -> None:
    plaintext = b"record bound to envelope 1"
    dek = generate_dek()
    aad1 = build_aad("env-1", None, "restricted", 1)
    aad2 = build_aad("env-2", None, "restricted", 1)

    encrypted = encrypt_payload(plaintext, dek, aad1)

    # Decrypting with wrong AAD (e.g. attempting to rebind to envelope 2) must fail
    with pytest.raises(InvalidTag):
        decrypt_payload(encrypted.ciphertext, encrypted.nonce, dek, aad2)


def test_dek_length_enforcement() -> None:
    with pytest.raises(ValueError, match="DEK must be 32 bytes"):
        encrypt_payload(b"data", b"short_key", b"aad")

    with pytest.raises(ValueError, match="DEK must be 32 bytes"):
        decrypt_payload(b"data", b"0" * 12, b"short_key", b"aad")


def test_nonce_length_enforcement() -> None:
    dek = generate_dek()
    with pytest.raises(ValueError, match="Nonce must be 12 bytes"):
        decrypt_payload(b"data", b"wrong_len", dek, b"aad")


def test_wrap_and_unwrap_dek_round_trip() -> None:
    dek = generate_dek()
    kek = generate_dek()
    kek_version = 1

    wrapped = wrap_dek(dek, kek, kek_version)
    assert wrapped.kek_version == 1

    unwrapped = unwrap_dek(wrapped.wrapped_dek_b64, kek)
    assert unwrapped == dek


def test_unwrap_dek_tampered_or_wrong_kek() -> None:
    dek = generate_dek()
    kek1 = generate_dek()
    kek2 = generate_dek()

    wrapped = wrap_dek(dek, kek1, 1)

    # Decrypting with wrong KEK raises InvalidTag
    with pytest.raises(InvalidTag):
        unwrap_dek(wrapped.wrapped_dek_b64, kek2)


def test_unwrap_dek_invalid_length() -> None:
    import base64

    short_blob = base64.b64encode(b"short").decode("ascii")
    with pytest.raises(ValueError, match="too short"):
        unwrap_dek(short_blob, generate_dek())


def test_normalize_index_value() -> None:
    assert normalize_index_value("  Fashion-MNIST  ") == "fashion-mnist"
    assert normalize_index_value("Class_Label\t") == "class_label"
    # Unicode NFC normalization
    assert normalize_index_value("Cafe\u0301") == "caf\u00e9"


def test_compute_hmac_token() -> None:
    key = generate_dek()
    token1 = compute_hmac_token("dataset-1", key)
    token2 = compute_hmac_token("dataset-1", key)
    token3 = compute_hmac_token("DATASET-1 ", key)  # Normalized match

    assert len(token1) == 32
    assert token1 == token2
    assert token1 == token3

    # Different value yields different token
    token_diff = compute_hmac_token("dataset-2", key)
    assert token1 != token_diff


def test_audit_hmac_and_chain_verification() -> None:
    audit_key = generate_dek()

    event1 = {
        "event_id": "e1",
        "event_type": "upload",
        "actor_id": "u1",
        "occurred_at": "2026-10-13T10:00:00Z",
    }
    hmac1 = compute_audit_hmac(event1, None, audit_key)
    event1["event_hmac"] = hmac1

    event2 = {
        "event_id": "e2",
        "event_type": "access_request",
        "actor_id": "u2",
        "occurred_at": "2026-10-13T10:05:00Z",
    }
    hmac2 = compute_audit_hmac(event2, hmac1, audit_key)
    event2["event_hmac"] = hmac2

    # Verify clean chain
    valid, broken_idx = verify_audit_chain([event1, event2], audit_key)
    assert valid is True
    assert broken_idx is None

    # Verify tampering detection
    tampered_event1 = dict(event1)
    tampered_event1["actor_id"] = "attacker"
    valid_tampered, broken_idx = verify_audit_chain([tampered_event1, event2], audit_key)
    assert valid_tampered is False
    assert broken_idx == 0


def test_generate_token() -> None:
    t1 = generate_token()
    t2 = generate_token()
    assert len(t1) > 20
    assert t1 != t2
