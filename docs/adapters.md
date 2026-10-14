# CAS-SE Adapter Interfaces Guide

CAS-SE provides three pluggable adapter interfaces that allow adopting organizations to integrate the middleware with their existing infrastructure without modifying core middleware code.

## Integration registration

CAS-SE resolves each adapter lazily once per API process and retains it for the
life of that process. An organization supplies a factory path in the form
`package.module:callable`; the callable receives the validated CAS-SE
`Settings` object and returns an implementation of the relevant protocol.

```python
# company_cas/adapters.py
from app.adapters.storage import StorageAdapter
from app.core.config import Settings

def build_storage_adapter(settings: Settings) -> StorageAdapter:
    return CompanyBlobAdapter(endpoint=settings.object_storage_endpoint)
```

```dotenv
STORAGE_ADAPTER=company_blob
STORAGE_ADAPTER_FACTORY=company_cas.adapters:build_storage_adapter
KEY_SERVICE_ADAPTER=company_kms
KEY_SERVICE_ADAPTER_FACTORY=company_cas.adapters:build_key_service
IDENTITY_ADAPTER=company_oidc
IDENTITY_ADAPTER_FACTORY=company_cas.adapters:build_identity_adapter
```

CAS-SE refuses an unknown adapter name or a factory that does not satisfy the
protocol; it never silently falls back to local files or environment keys.

---

## 1. StorageAdapter (`app.adapters.storage.StorageAdapter`)

Abstracts the underlying object storage engine where encrypted ciphertext payloads reside.

### Contract
```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class StorageAdapter(Protocol):
    def put_object(self, key: str, data: bytes) -> str:
        """Upload ciphertext blob under key and return its storage URI/key."""
        ...

    def get_object(self, key: str) -> bytes:
        """Retrieve ciphertext blob by key. Raises KeyError if not found."""
        ...

    def delete_object(self, key: str) -> None:
        """Permanently remove ciphertext object. Raises KeyError if not found."""
        ...

    def health_check(self) -> bool:
        """Verify reachability and read/write availability."""
        ...
```

### Reference Implementations
- **`MinIOAdapter`**: Uses `boto3` for any S3-compatible object storage (MinIO, AWS S3, Cloudflare R2, Ceph).
- **`LocalFileAdapter`**: Stores blobs on the local filesystem with path-traversal prevention. Intended for development and automated testing only.

---

## 2. KeyServiceAdapter (`app.adapters.key_service.KeyServiceAdapter`)

Abstracts the Key Encryption Key (KEK) management layer used to wrap and unwrap Data Encryption Keys (DEKs).

### Contract
```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class KeyServiceAdapter(Protocol):
    def get_current_kek(self) -> tuple[bytes, int]:
        """Return (32_byte_key, current_version_int)."""
        ...

    def get_kek_by_version(self, version: int) -> bytes:
        """Return the 32-byte KEK for a specific historic version."""
        ...

    def rotate_kek(self) -> tuple[bytes, int]:
        """Generate and activate a new KEK version. Old versions remain accessible."""
        ...
```

### Reference Implementations
- **`EnvVarKeyService`**: Loads versioned 32-byte base64-encoded keys from environment variables (`CAS_KEK_V1`, `CAS_KEK_V2`, etc.).
- **`SplitKeyService`**: Simulates 2-of-3 Shamir Secret Sharing polynomial threshold reconstruction using `secretsharing`. Intended for academic evaluation.

---

## 3. IdentityAdapter (`app.adapters.identity.IdentityAdapter`)

Abstracts identity verification and role resolution to federate with corporate directory services (LDAP, OIDC, SAML).

### Contract
```python
import uuid
from typing import Protocol, runtime_checkable
from app.adapters.identity import CASUser

@runtime_checkable
class IdentityAdapter(Protocol):
    def resolve_user(self, token: str) -> CASUser:
        """Cryptographically validate token and return standard CASUser record."""
        ...

    def get_user_role(self, user_id: uuid.UUID) -> str:
        """Authoritatively resolve user role from backend directory."""
        ...
```

### Role Model
All identity adapters must map user roles to one of the 5 canonical CAS-SE roles:
- `admin`: Policy management, job approval/rejection, key rotation.
- `uploader`: Encrypted ingestion of dataset records.
- `trainer`: Scoped ML jobs receiving minimized feature vectors.
- `researcher`: Explicitly approved raw data or research jobs.
- `auditor`: Audit verification and anomaly inspection.

When an external identity adapter is configured, CAS-SE disables its reference
registration, login, refresh, and logout routes. On each verified request it
creates or refreshes a minimal `cas_users` projection (UUID, display fields,
active state, and adapter-authoritative role) so the schema overlay can retain
foreign-key audit and job records without becoming the source of identity
truth. Adapter implementations must provide a stable UUID for `CASUser.user_id`.
