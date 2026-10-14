"""Tests for Phase 2: Identity, Password Hashing, JWT, and Auth API Routes."""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.adapters.identity import IdentityAdapter
from app.api.auth import get_db
from app.core.config import get_settings
from app.main import app
from app.models.models import CASBase
from app.services.identity_service import (
    BuiltInIdentity,
    create_access_token,
    decode_access_token,
    generate_token,
    hash_password,
    hash_refresh_token,
    refresh_token_expiry,
    verify_password,
)

settings = get_settings()


# ---------------------------------------------------------------------------
# Unit tests: Cryptographic and Identity Primitives
# ---------------------------------------------------------------------------


def test_password_hashing_and_verification() -> None:
    plaintext = "SuperSecretPassword123!"
    hashed = hash_password(plaintext)

    assert hashed != plaintext
    assert hashed.startswith("$argon2id$")
    assert verify_password(plaintext, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_jwt_access_token_creation_and_decoding() -> None:
    user_id = uuid.uuid4()
    token = create_access_token(user_id, role="trainer")

    decoded_sub = decode_access_token(token)
    assert decoded_sub == str(user_id)


def test_jwt_expired_token_rejected() -> None:
    user_id = uuid.uuid4()
    past_time = datetime.now(UTC) - timedelta(minutes=10)
    payload = {
        "sub": str(user_id),
        "iat": int((past_time - timedelta(minutes=15)).timestamp()),
        "exp": int(past_time.timestamp()),
    }
    expired_token = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

    with pytest.raises(PermissionError, match="Invalid access token"):
        decode_access_token(expired_token)


def test_jwt_tampered_token_rejected() -> None:
    user_id = uuid.uuid4()
    token = create_access_token(user_id, role="researcher")
    tampered_token = token[:-5] + "XXXXX"

    with pytest.raises(PermissionError):
        decode_access_token(tampered_token)


def test_refresh_token_utilities() -> None:
    raw_token = generate_token()
    assert len(raw_token) > 20

    token_hash = hash_refresh_token(raw_token)
    assert len(token_hash) == 64
    assert token_hash == hash_refresh_token(raw_token)

    expiry = refresh_token_expiry()
    assert expiry > datetime.now(UTC)


def test_builtin_identity_protocol_compliance() -> None:
    class DummyUser:
        def __init__(self, uid: uuid.UUID, role: str) -> None:
            self.user_id = uid
            self.username = "test"
            self.role = role

    dummy_map = {}
    adapter = BuiltInIdentity(user_resolver=lambda uid: dummy_map.get(uid))
    assert isinstance(adapter, IdentityAdapter)

    uid = uuid.uuid4()
    user = DummyUser(uid, "trainer")
    dummy_map[uid] = user

    token = create_access_token(uid, "trainer")
    resolved = adapter.resolve_user(token)
    assert resolved.user_id == uid
    assert adapter.get_user_role(uid) == "trainer"


# ---------------------------------------------------------------------------
# Integration tests: Auth API Routes with Async SQLite
# ---------------------------------------------------------------------------


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
def test_client(async_test_db: AsyncSession) -> AsyncGenerator[TestClient]:
    async def override_get_db() -> AsyncGenerator[AsyncSession]:
        yield async_test_db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


def test_auth_register_and_login_flow(test_client: TestClient) -> None:
    # 1. Register valid user
    reg_payload = {
        "username": "alice_researcher",
        "email": "alice@example.com",
        "password": "CorrectPassword123!",
        "role": "researcher",
    }
    res = test_client.post("/auth/register", json=reg_payload)
    assert res.status_code == 201
    user_data = res.json()
    assert user_data["username"] == "alice_researcher"
    assert user_data["role"] == "researcher"
    assert "user_id" in user_data

    # 2. Duplicate username rejected
    dup_res = test_client.post("/auth/register", json=reg_payload)
    assert dup_res.status_code == 409
    assert dup_res.json()["detail"] == "Username already exists"

    # 3. Invalid role rejected
    invalid_role_payload = dict(reg_payload, username="bob", role="superadmin")
    invalid_res = test_client.post("/auth/register", json=invalid_role_payload)
    assert invalid_res.status_code == 422

    # 4. Login with bad password fails
    bad_login = test_client.post(
        "/auth/login",
        json={"username": "alice_researcher", "password": "WrongPassword!"},
    )
    assert bad_login.status_code == 401

    # 5. Login with correct password succeeds
    login_res = test_client.post(
        "/auth/login",
        json={"username": "alice_researcher", "password": "CorrectPassword123!"},
    )
    assert login_res.status_code == 200
    token_data = login_res.json()
    assert "access_token" in token_data
    assert "refresh_token" in token_data
    assert token_data["token_type"] == "bearer"


def test_auth_me_endpoint(test_client: TestClient) -> None:
    # Register and login
    test_client.post(
        "/auth/register",
        json={
            "username": "charlie_trainer",
            "password": "TrainerPassword123!",
            "role": "trainer",
        },
    )
    login_res = test_client.post(
        "/auth/login",
        json={"username": "charlie_trainer", "password": "TrainerPassword123!"},
    )
    token = login_res.json()["access_token"]

    # Call /auth/me with Bearer token
    me_res = test_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["username"] == "charlie_trainer"
    assert me_data["role"] == "trainer"

    # Call /auth/me without token fails
    unauth_res = test_client.get("/auth/me")
    assert unauth_res.status_code == 401


def test_auth_refresh_token_rotation_and_revocation(test_client: TestClient) -> None:
    # Register and login
    test_client.post(
        "/auth/register",
        json={
            "username": "david_auditor",
            "password": "AuditorPassword123!",
            "role": "auditor",
        },
    )
    login_res = test_client.post(
        "/auth/login",
        json={"username": "david_auditor", "password": "AuditorPassword123!"},
    )
    refresh_token_v1 = login_res.json()["refresh_token"]

    # Rotate refresh token
    refresh_res = test_client.post("/auth/refresh", json={"refresh_token": refresh_token_v1})
    assert refresh_res.status_code == 200
    new_tokens = refresh_res.json()
    refresh_token_v2 = new_tokens["refresh_token"]
    assert refresh_token_v2 != refresh_token_v1

    # Replay of old refresh token must be rejected
    replay_res = test_client.post("/auth/refresh", json={"refresh_token": refresh_token_v1})
    assert replay_res.status_code == 401

    # Logout revokes refresh_token_v2
    logout_res = test_client.post("/auth/logout", json={"refresh_token": refresh_token_v2})
    assert logout_res.status_code == 204

    # Using revoked token after logout must fail
    after_logout_res = test_client.post("/auth/refresh", json={"refresh_token": refresh_token_v2})
    assert after_logout_res.status_code == 401


def test_rate_limiting_on_login(test_client: TestClient) -> None:
    from app.core.rate_limit import limiter

    limiter.reset()

    # Register user first
    test_client.post(
        "/auth/register",
        json={
            "username": "rate_limit_user",
            "password": "Password123!",
            "role": "researcher",
        },
    )

    # Attempt logins up to the rate limit
    for _ in range(10):
        res = test_client.post(
            "/auth/login",
            json={"username": "rate_limit_user", "password": "Password123!"},
        )
        assert res.status_code == 200

    # 11th request should be rate-limited
    rate_limited_res = test_client.post(
        "/auth/login",
        json={"username": "alice_researcher", "password": "CorrectPassword123!"},
    )
    assert rate_limited_res.status_code == 429
    limiter.reset()
