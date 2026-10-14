"""Tests for IdentityAdapter interface and CASUser model."""

from __future__ import annotations

import uuid

import pytest

from app.adapters.identity import CASUser, IdentityAdapter


class DummyIdentityAdapter:
    """Mock adapter for protocol compliance testing."""

    def resolve_user(self, token: str) -> CASUser:
        return CASUser(
            user_id=uuid.uuid4(),
            username="testuser",
            role="researcher",
        )

    def get_user_role(self, user_id: uuid.UUID) -> str:
        return "researcher"


def test_identity_adapter_protocol_compliance() -> None:
    adapter = DummyIdentityAdapter()
    assert isinstance(adapter, IdentityAdapter)


@pytest.mark.parametrize("valid_role", ["admin", "uploader", "trainer", "researcher", "auditor"])
def test_cas_user_valid_roles(valid_role: str) -> None:
    user = CASUser(
        user_id=uuid.uuid4(),
        username=f"user_{valid_role}",
        role=valid_role,
        email=f"{valid_role}@example.com",
    )
    assert user.role == valid_role
    assert user.is_active is True


def test_cas_user_invalid_role_rejected() -> None:
    with pytest.raises(ValueError, match="Invalid CAS-SE role"):
        CASUser(
            user_id=uuid.uuid4(),
            username="bad_role_user",
            role="superadmin",
        )
