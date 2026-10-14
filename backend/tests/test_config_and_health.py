"""Tests for Core Settings and Health/Metrics API endpoints."""

from __future__ import annotations

import os

from fastapi.testclient import TestClient

from app.adapters.factory import build_key_service, build_storage_adapter
from app.adapters.storage import LocalFileAdapter
from app.core.config import Settings
from app.main import app


def integration_storage_factory(settings: Settings) -> LocalFileAdapter:
    """Example client-owned adapter factory used to exercise the plug-in boundary."""
    return LocalFileAdapter(settings.local_storage_path)


def test_settings_properties_and_defaults() -> None:
    settings = Settings(
        jwt_secret_key="custom_jwt_secret_key_1234567890",
        index_hmac_key="custom_index_hmac_key_123456789",
        audit_integrity_key="custom_audit_key_1234567890123",
    )
    assert settings.app_name == "CAS-SE"
    assert settings.index_hmac_key_bytes == b"custom_index_hmac_key_123456789"
    assert settings.audit_integrity_key_bytes == b"custom_audit_key_1234567890123"


def test_adapter_factories_support_client_owned_and_split_key_adapters(tmp_path) -> None:
    custom_settings = Settings(
        storage_adapter="client_storage",
        storage_adapter_factory=f"{__name__}:integration_storage_factory",
        local_storage_path=str(tmp_path),
    )
    storage = build_storage_adapter(custom_settings)
    assert isinstance(storage, LocalFileAdapter)
    assert storage.health_check() is True

    secret = os.urandom(32)
    from app.adapters.key_service import SplitKeyService

    shares = SplitKeyService.generate_shares(secret.hex())
    split_settings = Settings(
        key_service_adapter="split",
        split_key_shares=shares[:2],
        split_key_threshold=2,
    )
    key_service = build_key_service(split_settings)
    assert key_service.get_current_kek() == (secret, 1)


def test_health_endpoint() -> None:
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "CAS-SE"
    assert "version" in data


def test_metrics_endpoint() -> None:
    client = TestClient(app)
    response = client.get("/metrics")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
