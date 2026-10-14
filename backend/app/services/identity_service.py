"""
CAS-SE Built-In Identity Service

Reference implementation of the IdentityAdapter protocol using:
  - Argon2 password hashing via pwdlib
  - Short-lived JWT access tokens (HS256)
  - Refresh token rotation with server-side revocation

Security invariants:
  - Role is always resolved from the server-side database, never from the JWT payload.
  - Client-supplied user_id, role, or permissions are NEVER trusted.
  - Refresh tokens are hashed before storage; raw tokens are never persisted.
  - Logout revokes the refresh token immediately.
  - Rate limiting applied at the API layer (not here).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

from jose import JWTError, jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

from app.core.config import get_settings

settings = get_settings()

# Argon2id hasher (OWASP recommended parameters)
_hasher = PasswordHash([Argon2Hasher()])


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


# Precomputed Argon2id dummy hash for constant-time rejection of non-existent users
DUMMY_ARGON2_HASH = _hasher.hash("dummy_constant_time_passphrase_value")


def hash_password(plaintext: str) -> str:
    """Hash a plaintext password with Argon2id."""
    return _hasher.hash(plaintext)


def verify_password(plaintext: str, hashed: str) -> bool:
    """Verify a plaintext password against an Argon2id hash."""
    try:
        return _hasher.verify(plaintext, hashed)
    except Exception:
        return False


def dummy_verify_password(plaintext: str) -> bool:
    """Perform dummy Argon2 verification to neutralize user enumeration timing attacks."""
    try:
        return _hasher.verify(plaintext, DUMMY_ARGON2_HASH)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# JWT access tokens
# ---------------------------------------------------------------------------


def create_access_token(user_id: uuid.UUID, role: str) -> str:
    """
    Create a short-lived JWT access token.

    The payload includes only `sub` (user_id as string) and `exp`.
    Role is NOT included in the token -- it is resolved server-side on every request.
    """
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    return str(jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm))


def decode_access_token(token: str) -> str:
    """
    Decode and verify a JWT access token.

    :returns: user_id string from the `sub` claim.
    :raises PermissionError: If the token is invalid, expired, or malformed.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        sub = payload.get("sub")
        if not sub:
            raise PermissionError("Token missing subject claim")
        return str(sub)
    except JWTError as e:
        raise PermissionError(f"Invalid access token: {e}") from e


# ---------------------------------------------------------------------------
# Refresh tokens
# ---------------------------------------------------------------------------


def hash_refresh_token(raw_token: str) -> str:
    """Hash a raw refresh token for storage. SHA-256 is sufficient here
    because tokens are already high-entropy random strings."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def refresh_token_expiry() -> datetime:
    """Return the expiry datetime for a new refresh token."""
    return datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days)


def generate_token(n_bytes: int = 32) -> str:
    """Generate a high-entropy URL-safe random token string."""
    import secrets

    return secrets.token_urlsafe(n_bytes)


class BuiltInIdentity:
    """
    Reference implementation of the IdentityAdapter protocol.
    Integrates CAS-SE JWT authentication with authoritative server-side user lookup.
    """

    def __init__(
        self,
        user_resolver: object | None = None,
    ) -> None:
        self._user_resolver = user_resolver

    def resolve_user(self, token: str) -> object:

        sub = decode_access_token(token)
        uid = uuid.UUID(sub)
        if callable(self._user_resolver):
            resolved = self._user_resolver(uid)
            if resolved:
                return resolved
        raise PermissionError(f"User {uid} not found or inactive")

    def get_user_role(self, user_id: uuid.UUID) -> str:
        if callable(self._user_resolver):
            resolved = self._user_resolver(user_id)
            if resolved and hasattr(resolved, "role"):
                return str(resolved.role)
        raise KeyError(f"User role not found for {user_id}")
