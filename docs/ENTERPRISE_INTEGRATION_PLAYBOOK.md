# CAS-SE Enterprise Integration Playbook

This guide explains how a client uses CAS-SE as a security architecture inside
their existing backend. CAS-SE is **not** the client’s web application and it
does not replace their user interface, domain services, identity provider,
database, object storage, or key-management system.

CAS-SE is the protected-data boundary between a client’s application services
and sensitive binary records. The client calls its API from their own backend;
their UI continues to call their backend as it does today. The bundled
`frontend/` is a demonstration console only and is not part of a production
integration.

## 1. What the client deploys

```text
Client UI / mobile app / partner API
                 |
                 v
      Client backend and business services
       |                         |
       | normal product APIs     | internal HTTPS + service identity
       |                         v
       |                    CAS-SE service
       |              (encryption, policy, audit)
       |                  |       |        |
       v                  v       v        v
Client domain DB       Client IdP Client KMS Client private object storage
                         / SSO      / HSM      (ciphertext only)
```

CAS-SE stores its own isolated `cas_*` tables in a PostgreSQL database. It
does not need to alter the client’s business tables. It stores ciphertext in a
private object store through a client-supplied adapter; it never writes raw
upload bytes to its relational database.

| Component | Client owns | CAS-SE does |
| --- | --- | --- |
| UI and public API | Screens, workflows, tenant rules, API contracts | Nothing; it is backend-only |
| Identity provider | Token issuance, revocation, group/role source | Validates via the identity adapter and projects an authorized actor |
| Object store | Private bucket/container, retention, network policy | Stores and retrieves ciphertext through the storage adapter |
| KMS/HSM | KEK custody, access policy, rotation | Requests DEK wrapping/unwrapping; never needs the raw KEK |
| PostgreSQL | Backup, availability, database access | Envelope metadata, protected indexes, policy versions, ML jobs, audit data |
| Policy ownership | Approves the organization’s authorization rules | Sends contextual data to OPA and fails closed on a denial/error |

## 2. The three normal request paths

### Ingest a sensitive file

1. The client backend authenticates its caller and sends the file to
   `POST /envelopes` with the caller’s bearer token.
2. CAS-SE validates the upload, creates a fresh DEK, encrypts the payload with
   AES-GCM, and binds its envelope metadata as authenticated data.
3. The configured KMS adapter wraps the DEK. The KMS implementation returns a
   wrapped-DEK value and a key version; the KEK itself stays in the client KMS
   or HSM.
4. CAS-SE writes ciphertext to the client’s private storage adapter. It stores
   envelope metadata and the wrapped DEK in PostgreSQL.
5. A supplied `dataset_id` is transformed into a keyed protected scope token.
   CAS-SE also creates keyed equality-search tokens. Plain dataset identifiers
   are not persisted for new envelopes.
6. CAS-SE returns an opaque `envelope_id` and appends an audit event.

The client keeps its own domain record and associates it with that
`envelope_id`; it does not use a storage URI as an application identifier.

### Find records without a plaintext database index

The client backend calls `POST /search` with either `dataset_id` or
`class_label` and a value. CAS-SE computes a keyed token and queries
`cas_protected_indexes`. It returns only envelope metadata, not storage
locations, dataset identifiers, plaintext, or keys.

Equality search intentionally leaks whether the *same* value was searched or
indexed more than once. Use restrictive database access, rotate the index key
under a migration plan, and do not treat it as a general encrypted-query
system.

### Request an approved, minimized view for ML

1. A trainer submits `POST /ml-jobs` with a purpose, requested view, raw
   dataset scope, and bounded duration.
2. CAS-SE converts the requested scope to protected tokens before persistence.
3. An authorized approver calls `POST /ml-jobs/{job_id}/approve`. CAS-SE
   creates and signs the persisted manifest internally; no reusable manifest
   secret is returned in the API response or audit log.
4. A client-controlled worker/orchestrator uses the job ID to run the internal
   feature-extraction task. The worker reloads and verifies the signed
   manifest before processing.
5. For each `POST /access-request`, CAS-SE checks the actor, purpose, job
   status, expiry, requested view, and protected dataset scope with OPA. A
   failure to reach OPA is a denial.

By default, design client ML systems around `feature_only` or metadata views.
Do not give training machines direct access to the ciphertext bucket, database
credentials, or KMS permissions.

## 3. Integrate client infrastructure through adapters

Adapter factories are the integration seam. Each factory receives immutable
CAS-SE `Settings` and returns an object that implements the relevant protocol.
Configure a callable with `package.module:callable`; do not edit route code to
add a customer integration.

```dotenv
# Values are examples of names only. Put real values in the client secret manager.
ENVIRONMENT=production
DATABASE_URL=postgresql+asyncpg://cas_service@postgres.internal/client_security
OPA_URL=http://opa.internal:8181
REDIS_URL=redis://redis.internal:6379/0

STORAGE_ADAPTER=client_storage
STORAGE_ADAPTER_FACTORY=client_cas.adapters:build_storage_adapter
KEY_SERVICE_ADAPTER=client_kms
KEY_SERVICE_ADAPTER_FACTORY=client_cas.adapters:build_key_service
IDENTITY_ADAPTER=client_oidc
IDENTITY_ADAPTER_FACTORY=client_cas.adapters:build_identity_adapter

# Generate distinct, high-entropy production values; never commit them.
JWT_SECRET_KEY=<secret-manager-reference>
INDEX_HMAC_KEY=<secret-manager-reference>
AUDIT_INTEGRITY_KEY=<secret-manager-reference>
MANIFEST_SIGNING_KEY=<secret-manager-reference>
```

### Storage adapter

Implement [`StorageAdapter`](../backend/app/adapters/storage.py). It must put,
get, delete, and health-check opaque ciphertext blobs. It must use private
storage and randomized object keys. CAS-SE passes ciphertext bytes only.

```python
def build_storage_adapter(settings):
    return ClientPrivateBucket(
        bucket=settings.object_storage_bucket,
        workload_identity="cas-se",
    )
```

The supplied local filesystem adapter and environment-variable key service are
for development or demonstration. A production client should use their cloud
KMS, Vault Transit, or HSM-backed service and a private object store.

### KMS/HSM adapter

Implement [`KeyServiceAdapter`](../backend/app/adapters/key_service.py). The
production contract deliberately operates on DEKs rather than returning KEK
material:

```python
class ClientKmsAdapter:
    def wrap_dek(self, dek: bytes) -> tuple[str, int]:
        """Ask the KMS to wrap a DEK; return opaque wrapped data and key version."""

    def unwrap_dek(self, wrapped_dek: str, version: int) -> bytes:
        """Ask the KMS to unwrap a DEK after its authorization checks."""

    def current_kek_version(self) -> int:
        """Return the KMS key version used for new envelopes."""

    def rotate_kek(self) -> int:
        """Initiate or record a KMS rotation and return the new version."""

def build_key_service(settings):
    return ClientKmsAdapter()
```

Grant this workload identity only the KMS operations it needs. It must not be
able to export a KEK, and application logs must never include DEKs, wrapped
DEKs, or KMS credentials. CAS-SE rewraps envelope DEKs during rotation instead
of re-encrypting ciphertext payloads.

### Identity adapter

Implement [`IdentityAdapter`](../backend/app/adapters/identity.py) to validate
the client’s OIDC, SAML, LDAP gateway, or internal session token. With an
external adapter, CAS-SE’s built-in registration, login, refresh, and logout
endpoints are disabled. The client remains the identity authority.

```python
import uuid
from app.adapters.identity import CASUser

class ClientOidcAdapter:
    def resolve_user(self, token: str) -> CASUser:
        claims = verify_with_client_jwks(token)  # validates signature, issuer, audience, expiry
        role = role_from_authoritative_groups(claims["groups"])
        return CASUser(
            # Map the stable external subject deterministically to a UUID,
            # or maintain an approved subject-to-UUID mapping in the client system.
            user_id=uuid.uuid5(uuid.NAMESPACE_URL, f"client-idp:{claims['sub']}"),
            username=claims["preferred_username"],
            role=role,
            email=claims.get("email"),
        )

    def get_user_role(self, user_id: uuid.UUID) -> str:
        return lookup_authoritative_role(user_id)

def build_identity_adapter(settings):
    return ClientOidcAdapter()
```

Allowed CAS-SE roles are `admin`, `uploader`, `trainer`, `researcher`, and
`auditor`. Map roles server-side from authoritative group membership. Never
accept a caller-provided role claim without verification.

## 4. Client-backend API examples

The client backend calls CAS-SE over private HTTPS. Do not invoke it directly
from a browser and do not expose CAS-SE storage or KMS credentials to the UI.

```python
import httpx

async def ingest_for_client(cas_url: str, token: str, payload: bytes) -> str:
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            f"{cas_url}/envelopes",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("upload.png", payload, "image/png")},
            data={
                "dataset_id": "research-cohort-2026-q1",
                "class_label": "approved-study",
                "sensitivity_label": "restricted",
            },
        )
        response.raise_for_status()
        return response.json()["envelope_id"]

async def find_in_scope(cas_url: str, token: str) -> list[dict]:
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            f"{cas_url}/search",
            headers={"Authorization": f"Bearer {token}"},
            json={"field_name": "dataset_id", "value": "research-cohort-2026-q1"},
        )
        response.raise_for_status()
        return response.json()

async def request_training_job(cas_url: str, token: str) -> dict:
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            f"{cas_url}/ml-jobs",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "purpose": "Evaluate approved model drift for the Q1 research cohort",
                "dataset_scope": ["research-cohort-2026-q1"],
                "requested_view": "feature_only",
                "duration_hours": 24,
            },
        )
        response.raise_for_status()
        return response.json()
```

The public API intentionally does not return a storage URI, original dataset
identifier, plaintext search index, or manifest signing token. Persist only the
opaque envelope/job IDs needed by the client’s domain model.

## 5. Policy integration

Deploy the CAS-SE OPA policy under package `cas_se.access`, matching the
default `OPA_POLICY_PATH=cas_se/access`. CAS-SE sends OPA a structured input
containing:

- identity: the validated actor and CAS-SE role;
- resource: envelope metadata and its protected `dataset_scope_token`;
- context: purpose, requested view, job status/expiry, and the job’s protected
  scope.

The policy must make its authorization decision from these inputs and return
the supported decision shape expected by CAS-SE. Start from
[`opa/policies/cas_se/access.rego`](../opa/policies/cas_se/access.rego), test
every role/view combination in staging, and version policy changes through the
CAS-SE policy API. A policy outage or malformed decision denies the request.

## 6. Deployment and rollout

1. **Choose ownership boundaries.** Identify the client IdP, KMS/HSM, private
   storage, PostgreSQL database, OPA service, Redis broker, and the service
   identities that may call each.
2. **Build adapters and configure secrets.** Add the integration package to
   the CAS-SE image or Python environment. Use workload identity and a secret
   manager rather than literal environment secrets.
3. **Deploy dependencies privately.** Restrict network paths so only approved
   client services can reach CAS-SE; restrict CAS-SE to PostgreSQL, OPA, Redis,
   KMS, and the private object store.
4. **Apply migrations.** From `backend/`, run:

   ```bash
   python -m alembic upgrade head
   ```

   This creates the CAS-SE schema overlay including `cas_data_envelopes`,
   `cas_protected_indexes`, `cas_ml_jobs`, `cas_policy_versions`,
   `cas_access_audit`, and related `cas_*` tables.
5. **Validate in staging.** Test ingest, protected search, denied access,
   approval, manifest verification, worker access, KMS rotation, audit-chain
   verification, and OPA outage behavior with representative client tokens.
6. **Roll out behind the client backend.** Start with one data class or tenant,
   monitor audit events and denials, then expand deliberately.

### Existing envelopes and migration 002

Migration `002_protected_scopes` adds `dataset_scope_token` for new strict
scope enforcement. It does not invent tokens for legacy rows because doing so
requires the original dataset identifier. Before relying exclusively on strict
scope matching, run a client-controlled re-ingestion or backfill process that
recreates protected indexes and scope tokens from an approved source of truth.
Until then, legacy records follow the compatibility path and should be tracked
as migration debt.

## 7. Operational runbook

| Event | Expected CAS-SE behavior | Client response |
| --- | --- | --- |
| Invalid/expired IdP token | Deny before data access | Refresh/re-authenticate through the client IdP |
| OPA unavailable or malformed response | Deny access (fail closed) | Restore OPA; do not bypass CAS-SE |
| Storage/KMS operation fails | Return a generic failure and audit the event | Investigate through service logs/telemetry without exposing secrets |
| Job expires or scope does not match | Deny access | Submit a new, appropriately scoped job for approval |
| Key rotation | Adapter controls new key version; CAS-SE rewraps DEKs | Retain old KMS key versions until all dependent envelopes are rewrapped |
| Suspected audit tampering | Chain verification fails | Preserve evidence, restrict access, and investigate using independent log retention |

The audit chain is tamper-evident, not a substitute for independent immutable
log retention, backups, incident response, or the client’s compliance program.
CAS-SE provides technical controls; the client remains the data controller and
is responsible for legal, contractual, retention, consent, and regulatory
requirements.

## 8. Production acceptance checklist

- [ ] The client UI reaches CAS-SE only through the client backend.
- [ ] Production uses external identity, private storage, and a non-exportable
      KMS/HSM adapter; reference adapters are not used.
- [ ] Workload identities have least-privilege network, storage, database, and
      KMS permissions.
- [ ] Distinct secret-manager values exist for JWT, protected index, audit
      integrity, and manifest signing keys.
- [ ] OPA has been tested for allow, deny, expiry, scope mismatch, and outage.
- [ ] Worker nodes lack direct object-store/KMS credentials except through the
      approved CAS-SE path.
- [ ] Existing records have a signed-off protected-scope migration plan.
- [ ] Monitoring covers service health, policy denials, KMS/storage errors,
      worker failures, and audit-chain verification.

For local setup and adapter details, see
[`docs/adapters.md`](adapters.md),
[`docs/integration_guide.md`](integration_guide.md), and
[`.env.example`](../.env.example).
