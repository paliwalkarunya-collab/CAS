"""Tests for KeyServiceAdapter, EnvVarKeyService, and SplitKeyService."""

from __future__ import annotations

import base64
import os

import pytest

from app.adapters.key_service import EnvVarKeyService, KeyServiceAdapter, SplitKeyService


def test_key_service_protocol_compliance(monkeypatch: pytest.MonkeyPatch) -> None:
    raw_key = os.urandom(32)
    b64_key = base64.b64encode(raw_key).decode()
    monkeypatch.setenv("CAS_KEK_V1", b64_key)
    monkeypatch.setenv("CAS_KEK_CURRENT_VERSION", "1")

    service = EnvVarKeyService()
    assert isinstance(service, KeyServiceAdapter)


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
    with pytest.raises(EnvironmentError, match="must be an integer"):
        EnvVarKeyService()


def test_env_var_key_service_missing_current_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAS_KEK_CURRENT_VERSION", "99")
    with pytest.raises(EnvironmentError, match="CAS_KEK_V99 is not set"):
        EnvVarKeyService()


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
