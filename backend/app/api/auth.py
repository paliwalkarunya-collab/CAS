"""
CAS-SE Authentication API Routes

Reference implementation of the IdentityAdapter using CAS-SE's own JWT/Argon2.
Organizations may replace this with their OIDC, LDAP, or SAML adapter.

Security notes:
  - Role is ALWAYS resolved from the database, never from token payload.
  - Refresh tokens are stored hashed; raw tokens are never persisted.
  - Logout immediately revokes the refresh token.
  - Login returns minimal user info -- no internal IDs exposed unnecessarily.
"""

from __future__ import annotations

import json
import urllib.parse
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.factory import AdapterConfigurationError, build_identity_adapter
from app.core.config import get_settings
from app.core.rate_limit import limiter
from app.db.session import get_db
from app.models.models import CASRefreshToken, CASUser
from app.services import identity_service
from app.services.audit import append_audit_event

router = APIRouter()
settings = get_settings()
bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Schemas (centralised in app.schemas per PRD §10.3)
# ---------------------------------------------------------------------------

from app.schemas.auth import (  # noqa: E402
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)

# ---------------------------------------------------------------------------
# Dependency: current user from JWT
# ---------------------------------------------------------------------------


def _require_builtin_identity() -> None:
    """Keep the reference password endpoints out of federated deployments."""
    if settings.identity_adapter != "builtin":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Built-in authentication is disabled; use the configured identity provider",
        )


async def _resolve_external_user(
    token: str,
    request: Request,
    db: AsyncSession,
) -> CASUser:
    """Verify a federated token and keep a minimal CAS-SE identity projection.

    CAS-SE only stores the UUID, display data, active flag, and canonical role
    needed for its overlay foreign keys and policy input. The adapter remains
    responsible for cryptographic token verification and authoritative mapping.
    """
    adapter = getattr(request.app.state, "cas_identity_adapter", None)
    if adapter is None:
        try:
            adapter = build_identity_adapter(settings)
        except AdapterConfigurationError:
            raise HTTPException(
                status_code=500, detail="Identity adapter is not configured"
            ) from None
        request.app.state.cas_identity_adapter = adapter
    if adapter is None:
        raise HTTPException(status_code=500, detail="Identity adapter is not configured")
    try:
        principal = adapter.resolve_user(token)
    except (PermissionError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from None
    except Exception:
        # Do not surface IdP implementation details, endpoint information, or
        # token-parsing errors to a caller.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identity verification failed",
        ) from None

    if not principal.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User account inactive"
        )

    result = await db.execute(select(CASUser).where(CASUser.id == principal.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        # Password auth is disabled for this identity projection. The marker
        # exists solely because the reference overlay retains a NOT NULL field
        # for built-in Argon2 hashes.
        user = CASUser(
            id=principal.user_id,
            username=principal.username,
            email=principal.email,
            hashed_password="!federated-identity-managed!",
            role=principal.role,
            is_active=True,
        )
        db.add(user)
    else:
        # Do not trust a stale local role when the client's IdP has changed it.
        user.username = principal.username
        user.email = principal.email
        user.role = principal.role
        user.is_active = True
    await db.flush()
    return user


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> CASUser:
    """
    Resolve the authenticated user from the JWT Bearer token.

    Role is resolved from the database -- NOT from the JWT payload.
    Raises 401 if the token is missing, invalid, or the user is inactive.
    """
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    if settings.identity_adapter != "builtin":
        return await _resolve_external_user(credentials.credentials, request, db)

    try:
        user_id_str = identity_service.decode_access_token(credentials.credentials)
        user_id = uuid.UUID(user_id_str)
    except (PermissionError, ValueError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from e

    result = await db.execute(select(CASUser).where(CASUser.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def require_roles(*roles: str) -> Callable[[CASUser], Awaitable[CASUser]]:
    """Dependency factory: require the current user to have one of `roles` (admin has all powers)."""

    async def _check(current_user: CASUser = Depends(get_current_user)) -> CASUser:
        if current_user.role != "admin" and current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role}' is not permitted for this action",
            )
        return current_user

    return _check


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """
    Register a new CAS-SE user.

    In production, self-registration cannot create administrative accounts.
    Only the initial bootstrap user (when no users exist) or an existing admin
    may assign the admin role.
    """
    _require_builtin_identity()

    # Prevent unauthenticated privilege escalation to admin role (CWE-269)
    if body.role == "admin":
        count_res = await db.execute(select(func.count(CASUser.id)))
        user_count = count_res.scalar_one() or 0
        if user_count > 0:
            auth_header = request.headers.get("authorization")
            is_admin_caller = False
            if auth_header and auth_header.startswith("Bearer "):
                try:
                    token = auth_header.split(" ", 1)[1]
                    sub = identity_service.decode_access_token(token)
                    caller_res = await db.execute(
                        select(CASUser).where(
                            CASUser.id == uuid.UUID(sub), CASUser.is_active.is_(True)
                        )
                    )
                    caller = caller_res.scalar_one_or_none()
                    if caller and caller.role == "admin":
                        is_admin_caller = True
                except Exception:
                    pass
            if not is_admin_caller:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Admin role can only be assigned by an existing administrator",
                )

    # Check for duplicate username
    existing = await db.execute(select(CASUser).where(CASUser.username == body.username))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username already exists")

    # Check for duplicate email if provided
    if body.email:
        existing_email = await db.execute(select(CASUser).where(CASUser.email == body.email))
        if existing_email.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already exists")

    user = CASUser(
        id=uuid.uuid4(),
        username=body.username,
        email=body.email,
        hashed_password=identity_service.hash_password(body.password),
        role=body.role,
        is_active=True,
    )
    db.add(user)
    await db.flush()
    return UserResponse(
        user_id=user.id,
        username=user.username,
        role=user.role,
        email=user.email,
        is_active=user.is_active,
    )


@router.post("/login", response_model=TokenResponse)
@limiter.limit(settings.rate_limit_login)
async def login(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """
    Authenticate and return access + refresh tokens.

    Supports both application/json and application/x-www-form-urlencoded formats.
    Rate limited and audited.
    """
    _require_builtin_identity()
    username: str | None = None
    password: str | None = None

    content_type = request.headers.get("content-type", "")
    body_bytes = await request.body()

    if "application/json" in content_type:
        try:
            data = json.loads(body_bytes)
            if isinstance(data, dict):
                username = data.get("username")
                password = data.get("password")
        except Exception:
            pass
    elif "application/x-www-form-urlencoded" in content_type:
        try:
            parsed = urllib.parse.parse_qs(body_bytes.decode("utf-8", errors="replace"))
            username = parsed.get("username", [None])[0]
            password = parsed.get("password", [None])[0]
        except Exception:
            pass

    if not username or not password:
        # Fallback heuristic: try parsing as JSON, then form
        try:
            data = json.loads(body_bytes)
            if isinstance(data, dict):
                username = data.get("username")
                password = data.get("password")
        except Exception:
            try:
                parsed = urllib.parse.parse_qs(body_bytes.decode("utf-8", errors="replace"))
                username = parsed.get("username", [None])[0]
                password = parsed.get("password", [None])[0]
            except Exception:
                pass

    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Username and password are required",
        )

    login_req = LoginRequest(username=username, password=password)

    result = await db.execute(
        select(CASUser).where(CASUser.username == login_req.username, CASUser.is_active.is_(True))
    )
    user = result.scalar_one_or_none()

    valid_password = False
    if user:
        valid_password = identity_service.verify_password(login_req.password, user.hashed_password)
    else:
        # Constant-time dummy verification to mitigate username enumeration (CWE-208)
        identity_service.dummy_verify_password(login_req.password)

    if not user or not valid_password:
        await append_audit_event(
            db=db,
            event_type="login",
            decision="deny",
            reason="Invalid credentials",
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    access_token = identity_service.create_access_token(user.id, user.role)
    raw_refresh = identity_service.generate_token()
    token_hash = identity_service.hash_refresh_token(raw_refresh)
    expiry = identity_service.refresh_token_expiry()

    refresh_record = CASRefreshToken(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expiry,
    )
    db.add(refresh_record)
    await db.flush()

    await append_audit_event(
        db=db,
        event_type="login",
        actor_id=user.id,
        actor_role=user.role,
        decision="allow",
        reason="User authenticated successfully",
    )
    await db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        role=user.role,
        username=user.username,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    """
    Rotate a refresh token -- issue new access + refresh tokens and revoke the old one.

    Implements refresh-token rotation: the submitted token is immediately revoked
    and a new pair is issued. Detecting re-use of a revoked token is a signal of
    token theft.
    """
    _require_builtin_identity()
    token_hash = identity_service.hash_refresh_token(body.refresh_token)
    result = await db.execute(
        select(CASRefreshToken).where(
            CASRefreshToken.token_hash == token_hash,
            CASRefreshToken.is_revoked.is_(False),
        )
    )
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    record_expiry = (
        record.expires_at if record.expires_at.tzinfo else record.expires_at.replace(tzinfo=UTC)
    )
    if record_expiry < datetime.now(UTC):
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    # Revoke old token
    record.is_revoked = True
    record.revoked_at = datetime.now(UTC)
    await db.flush()

    # Fetch user (re-verify is_active)
    user_result = await db.execute(
        select(CASUser).where(CASUser.id == record.user_id, CASUser.is_active.is_(True))
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User account inactive")

    access_token = identity_service.create_access_token(user.id, user.role)
    raw_refresh = identity_service.generate_token()
    new_hash = identity_service.hash_refresh_token(raw_refresh)

    new_record = CASRefreshToken(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=new_hash,
        expires_at=identity_service.refresh_token_expiry(),
    )
    db.add(new_record)
    await db.flush()

    return TokenResponse(access_token=access_token, refresh_token=raw_refresh)


@router.post("/logout", status_code=204)
async def logout(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Revoke the given refresh token on logout."""
    _require_builtin_identity()
    token_hash = identity_service.hash_refresh_token(body.refresh_token)
    result = await db.execute(
        select(CASRefreshToken).where(CASRefreshToken.token_hash == token_hash)
    )
    record = result.scalar_one_or_none()
    if record and not record.is_revoked:
        record.is_revoked = True
        record.revoked_at = datetime.now(UTC)
        await append_audit_event(
            db=db,
            event_type="logout",
            actor_id=record.user_id,
            decision="allow",
            reason="User logged out and token revoked",
        )
        await db.commit()


@router.get("/me", response_model=UserResponse)
async def me(current_user: CASUser = Depends(get_current_user)) -> UserResponse:
    """Return the authenticated user's profile. Role resolved from DB."""
    return UserResponse(
        user_id=current_user.id,
        username=current_user.username,
        role=current_user.role,
        email=current_user.email,
        is_active=current_user.is_active,
    )
