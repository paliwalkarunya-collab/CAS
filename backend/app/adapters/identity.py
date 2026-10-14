"""
CAS-SE Identity Adapter Interface

Defines the pluggable identity/authentication backend contract.
Organizations implement this to federate CAS-SE with their existing LDAP,
OIDC, SAML, or internal user directory instead of using CAS-SE's built-in
JWT/Argon2 reference implementation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass
class CASUser:
    """
    Canonical CAS-SE user record returned by any identity adapter.

    The `role` field drives OPA policy evaluation -- it must be one of the
    recognised CAS-SE roles: admin, uploader, trainer, researcher, auditor.
    """

    user_id: uuid.UUID
    username: str
    role: str
    email: str | None = None
    is_active: bool = True

    def __post_init__(self) -> None:
        valid_roles = {"admin", "uploader", "trainer", "researcher", "auditor"}
        if self.role not in valid_roles:
            raise ValueError(f"Invalid CAS-SE role {self.role!r}. Must be one of: {valid_roles}")


@runtime_checkable
class IdentityAdapter(Protocol):
    """
    Pluggable identity / authentication backend protocol.

    Implementations MUST:
    - Verify the token cryptographically -- never trust client-supplied role claims.
    - Resolve the canonical CAS-SE role from a server-side authoritative source.
    - Raise ValueError / PermissionError for invalid, expired, or revoked tokens.
    """

    def resolve_user(self, token: str) -> CASUser:
        """
        Validate `token` and return the corresponding CASUser.

        :param token: Raw bearer token (JWT, opaque session token, etc.)
        :raises ValueError: If the token is malformed.
        :raises PermissionError: If the token is expired, revoked, or invalid.
        """
        ...

    def get_user_role(self, user_id: uuid.UUID) -> str:
        """
        Return the authoritative CAS-SE role for a given user ID.
        Never derive role from the token payload alone.
        """
        ...
