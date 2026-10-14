"""
CAS-SE Core Configuration

All runtime configuration is loaded from environment variables.
Secrets are never logged, printed, or included in stack traces.
Use `.env.example` as a reference; copy to `.env` for local development.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -----------------------------------------------------------------------
    # Application
    # -----------------------------------------------------------------------
    app_name: str = "CAS-SE"
    app_version: str = "0.1.0"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = False

    # -----------------------------------------------------------------------
    # Database (PostgreSQL / compatible RDBMS)
    # Organization provides their own PostgreSQL instance.
    # -----------------------------------------------------------------------
    database_url: str = "postgresql+asyncpg://cas_user:cas_pass@localhost:5432/cas_db"

    # -----------------------------------------------------------------------
    # Object Storage (S3-compatible)
    # -----------------------------------------------------------------------
    storage_adapter: str = "local"
    # A dotted callable path (``package.module:factory``) for an organization
    # supplied adapter. The callable receives ``Settings`` and returns an
    # adapter conforming to the relevant CAS-SE protocol.
    storage_adapter_factory: str | None = None
    object_storage_endpoint: str = "http://localhost:9000"
    object_storage_access_key: str = "minioadmin"
    object_storage_secret_key: str = "minioadmin"
    object_storage_bucket: str = "cas-se-envelopes"
    object_storage_use_ssl: bool = False
    local_storage_path: str = "./local_storage"

    # -----------------------------------------------------------------------
    # Key Management
    # -----------------------------------------------------------------------
    key_service_adapter: str = "env"
    key_service_adapter_factory: str | None = None
    cas_kek_current_version: int = 1
    # Individual KEK versions read directly from env: CAS_KEK_V1, CAS_KEK_V2, ...
    split_key_shares: list[str] = []
    split_key_threshold: int = 2

    # -----------------------------------------------------------------------
    # Identity / Authentication
    # -----------------------------------------------------------------------
    identity_adapter: str = "builtin"
    identity_adapter_factory: str | None = None
    jwt_secret_key: str = "CHANGEME-replace-with-256bit-random-secret"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # HMAC key for protected indexes (separate from KEK)
    index_hmac_key: str = "CHANGEME-replace-with-256bit-random-hmac-key"

    # HMAC key for audit chain integrity (separate from all others)
    audit_integrity_key: str = "CHANGEME-replace-with-256bit-random-audit-key"

    # HMAC key used exclusively to authenticate persisted ML job manifests.
    # It is intentionally distinct from audit and protected-index keys.
    manifest_signing_key: str = "CHANGEME-replace-with-256bit-random-manifest-key"

    # -----------------------------------------------------------------------
    # OPA (Open Policy Agent)
    # -----------------------------------------------------------------------
    opa_url: str = "http://localhost:8181"
    opa_policy_path: str = "cas_se/access"
    opa_timeout_seconds: float = 3.0

    # -----------------------------------------------------------------------
    # Redis / Worker
    # -----------------------------------------------------------------------
    redis_url: str = "redis://localhost:6379/0"

    # -----------------------------------------------------------------------
    # Security / CORS
    # -----------------------------------------------------------------------
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]
    max_upload_bytes: int = 10 * 1024 * 1024  # 10 MB
    allowed_extensions: list[str] = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"]
    rate_limit_login: str = "10/minute"
    rate_limit_access_request: str = "30/minute"

    @field_validator(
        "jwt_secret_key",
        "index_hmac_key",
        "audit_integrity_key",
        "manifest_signing_key",
    )
    @classmethod
    def warn_default_secrets(cls, v: str) -> str:
        if v.startswith("CHANGEME"):
            import warnings

            warnings.warn(
                "Secret key is set to default placeholder value. "
                "Generate a secure random key before any deployment.",
                stacklevel=2,
            )
        return v

    @model_validator(mode="after")
    def validate_production_secrets(self) -> Settings:
        if self.environment == "production":
            for key_name in (
                "jwt_secret_key",
                "index_hmac_key",
                "audit_integrity_key",
                "manifest_signing_key",
            ):
                val = getattr(self, key_name, "")
                if val.startswith("CHANGEME") or len(val) < 32:
                    raise ValueError(
                        f"Production environment requires a secure, non-default secret for '{key_name}' "
                        f"(must not start with 'CHANGEME' and must be at least 32 characters)."
                    )
        return self

    @property
    def index_hmac_key_bytes(self) -> bytes:
        return self.index_hmac_key.encode()

    @property
    def audit_integrity_key_bytes(self) -> bytes:
        return self.audit_integrity_key.encode()

    @property
    def manifest_signing_key_bytes(self) -> bytes:
        return self.manifest_signing_key.encode()


@lru_cache
def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    return Settings()
