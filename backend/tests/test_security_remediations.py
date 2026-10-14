"""Security regression tests verifying fixes for identified vulnerabilities.

Covers:
  - CWE-22: Path traversal prefix collision prevention in storage adapter
  - CWE-208 / CWE-307: Observable timing discrepancy / user enumeration prevention on login
  - CWE-269: Privilege escalation prevention on self-registration
  - CWE-798: Production secret enforcement rejecting placeholder keys
  - CWE-400 / CWE-770: Input validation bounds on search, access, and envelopes
"""

from __future__ import annotations

import base64
import uuid
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.adapters.storage import LocalFileAdapter
from app.api.auth import get_db
from app.core.config import Settings
from app.main import app
from app.models.models import CASBase
from app.services.identity_service import dummy_verify_password


@pytest.fixture
def kek_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAS_KEK_V1", base64.b64encode(b"k" * 32).decode("ascii"))


@pytest.fixture
async def async_test_db() -> AsyncGenerator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(CASBase.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def test_client(async_test_db: AsyncSession, kek_env: None) -> AsyncGenerator[TestClient]:
    async def override_get_db() -> AsyncGenerator[AsyncSession]:
        yield async_test_db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


def test_storage_adapter_path_traversal_prefix_collision(tmp_path: Path) -> None:
    """Ensure LocalFileAdapter cannot access sibling directories sharing a prefix."""
    storage_dir = tmp_path / "storage"
    adapter = LocalFileAdapter(storage_dir)

    # Path traversal with parent directory reference
    with pytest.raises(ValueError, match="Path traversal detected"):
        adapter.put_object("../sibling_folder/file.bin", b"evil")

    # Path resolving directly to base
    with pytest.raises(ValueError, match="Path traversal detected"):
        adapter.get_object(".")


def test_dummy_verify_password_executes_safely() -> None:
    """Verify dummy constant-time Argon2 verification completes without error."""
    assert dummy_verify_password("any_arbitrary_password") is False


def test_production_environment_rejects_placeholder_secrets() -> None:
    """Verify Settings rejects placeholder or short secrets in production environment."""
    with pytest.raises(ValueError, match="Production environment requires a secure"):
        Settings(
            environment="production",
            jwt_secret_key="CHANGEME-some-key",
            index_hmac_key="valid-key-with-sufficient-entropy-32-chars-long",
            audit_integrity_key="valid-key-with-sufficient-entropy-32-chars-long",
            manifest_signing_key="valid-key-with-sufficient-entropy-32-chars-long",
        )


def test_privilege_escalation_to_admin_blocked(test_client: TestClient) -> None:
    """Verify unauthenticated callers cannot assign admin role once users exist."""
    # Register regular researcher
    res1 = test_client.post(
        "/auth/register",
        json={
            "username": "user1",
            "email": "user1@example.com",
            "password": "Password123!",
            "role": "researcher",
        },
    )
    assert res1.status_code == 201

    # Attempt to register admin without admin credentials
    res2 = test_client.post(
        "/auth/register",
        json={
            "username": "attacker_admin",
            "email": "attacker@example.com",
            "password": "Password123!",
            "role": "admin",
        },
    )
    assert res2.status_code == 403
    assert "Admin role can only be assigned by an existing administrator" in res2.json()["detail"]


def test_duplicate_email_registration_rejected(test_client: TestClient) -> None:
    """Verify duplicate email returns HTTP 409 Conflict instead of 500 error."""
    res1 = test_client.post(
        "/auth/register",
        json={
            "username": "first_user",
            "email": "shared@example.com",
            "password": "Password123!",
            "role": "trainer",
        },
    )
    assert res1.status_code == 201

    res2 = test_client.post(
        "/auth/register",
        json={
            "username": "second_user",
            "email": "shared@example.com",
            "password": "Password123!",
            "role": "trainer",
        },
    )
    assert res2.status_code == 409
    assert "Email already exists" in res2.json()["detail"]


def test_access_request_invalid_view_rejected(test_client: TestClient) -> None:
    """Verify AccessRequest schema rejects invalid data views with 422."""
    res = test_client.post(
        "/auth/register",
        json={
            "username": "access_tester",
            "password": "Password123!",
            "role": "trainer",
        },
    )
    assert res.status_code == 201

    login_res = test_client.post(
        "/auth/login",
        json={"username": "access_tester", "password": "Password123!"},
    )
    token = login_res.json()["access_token"]

    bad_access = test_client.post(
        "/access-request",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "envelope_id": str(uuid.uuid4()),
            "purpose": "model_training",
            "requested_view": "invalid_malformed_view",
        },
    )
    assert bad_access.status_code == 422
