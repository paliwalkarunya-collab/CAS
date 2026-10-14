# CAS-SE Organization Integration & Adoption Guide

## 1. Executive Architecture Summary

**CAS-SE (Context-Aware, Searchable, Split-Key Data Envelope)** is a privacy-preserving data-governance middleware designed to integrate into an organization's existing storage, database, and machine learning infrastructure.

> CAS-SE is deployed behind the organization's existing application services.
> Its bundled React dashboard is a demonstration aid only and is not part of a
> client integration or production architecture.

### Adapter boundary for client backends

Install the client's adapter package alongside CAS-SE and configure factories;
do not fork route handlers to connect storage, KMS, or SSO:

```dotenv
STORAGE_ADAPTER=client_storage
STORAGE_ADAPTER_FACTORY=client_cas.adapters:build_storage_adapter
KEY_SERVICE_ADAPTER=client_kms
KEY_SERVICE_ADAPTER_FACTORY=client_cas.adapters:build_key_service
IDENTITY_ADAPTER=client_oidc
IDENTITY_ADAPTER_FACTORY=client_cas.adapters:build_identity_adapter
MANIFEST_SIGNING_KEY=<dedicated-high-entropy-secret>
```

Each factory receives validated CAS-SE settings and returns the corresponding
`StorageAdapter`, `KeyServiceAdapter`, or `IdentityAdapter`. CAS-SE validates
the contract on first use and fails closed if it cannot be constructed. With
an external identity adapter, CAS-SE password/session routes are disabled;
the client's IdP remains the authority for authentication and role mapping.

```
┌─────────────────────────────────────────────────────────────────┐
│                 ORGANIZATION'S APPLICATION TIER                 │
│              (Web Application, ML Pipeline, Data Platform)      │
└───────────────────────────────┬─────────────────────────────────┘
                                │  REST API (JWT Authenticated)
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     CAS-SE MIDDLEWARE LAYER                     │
│  ┌──────────────┐ ┌──────────────┐ ┌───────────┐ ┌───────────┐  │
│  │   Envelope   │ │ Policy Engine│ │   Audit   │ │    Key    │  │
│  │   Service    │ │    (OPA)     │ │  Service  │ │  Service  │  │
│  │  AES-256-GCM │ │ Context-Aware│ │ HMAC-256  │ │  Envelope │  │
│  │ Minimization │ │  Fail-Closed │ │Hash Chain │ │ Split-Key │  │
│  └──────┬───────┘ └──────┬───────┘ └─────┬─────┘ └─────┬─────┘  │
│         │                │               │             │        │
│  ┌──────┴────────────────┴───────────────┴─────────────┴─────┐  │
│  │                DATABASE ADAPTER INTERFACE                 │  │
│  │       (SQLAlchemy Async — Pluggable to any PostgreSQL)    │  │
│  └──────┬──────────────────────────────────────────────┬─────┘  │
└─────────┼──────────────────────────────────────────────┼────────┘
          │                                              │
          ▼                                              ▼
┌───────────────────┐                          ┌───────────────────┐
│  ORGANIZATION'S   │                          │  ORGANIZATION'S   │
│    PostgreSQL     │                          │  Object Storage   │
│  (Schema Overlay) │                          │ (S3 / MinIO / GCS)│
└───────────────────┘                          └───────────────────┘
```

### Core Architecture Invariants
1. **Never Store Raw Payloads in RDBMS**: Only metadata, wrapped DEKs, and HMAC tokens reside in PostgreSQL; encrypted ciphertext blobs reside in object storage.
2. **Context-Aware Fail-Closed Authorization**: Every sensitive read evaluates actor identity, role, purpose, dataset scope, job state, view type, and policy version against OPA. OPA unreachable = **Deny**.
3. **Pluggable Non-Disruptive Schema Overlay**: All tables use the `cas_*` prefix. Alembic migrations never modify existing organizational application tables.
4. **Data Minimization by Default**: ML trainers receive feature vector embeddings or masked representations from approved, active, scoped jobs—never raw images by default.
5. **Zero Secret Leakage**: DEKs, KEKs, nonces, and HMAC keys are never written to logs, error payloads, API responses, or frontend state.

---

## 2. Five-Step Integration Roadmap

### Step 1: Deploy Infrastructure Dependencies

CAS-SE requires:
- **PostgreSQL 14+** (Existing or managed instance)
- **S3-Compatible Object Store** (AWS S3, MinIO, Azure Blob, Google Cloud Storage)
- **Open Policy Agent (OPA) 0.60+** (Sidecar or cluster service)
- **Redis 7+** (For background worker queue and job manifest processing)

Example environment configuration (`.env`):
```bash
ENVIRONMENT=production
DATABASE_URL=postgresql+asyncpg://cas_user:strong_password@postgres.internal:5432/org_db
STORAGE_ADAPTER=minio
OBJECT_STORAGE_ENDPOINT=https://s3.internal:9000
OBJECT_STORAGE_ACCESS_KEY=your_access_key
OBJECT_STORAGE_SECRET_KEY=your_secret_key
OBJECT_STORAGE_BUCKET=org-encrypted-envelopes
KEY_SERVICE_ADAPTER=env
CAS_KEK_V1=<base64-encoded-32-byte-key>
CAS_KEK_CURRENT_VERSION=1
OPA_URL=http://opa.internal:8181
REDIS_URL=redis://redis.internal:6379/0
JWT_SECRET_KEY=<strong-random-jwt-key>
INDEX_HMAC_KEY=<strong-random-32-byte-key>
AUDIT_INTEGRITY_KEY=<strong-random-32-byte-key>
```

---

### Step 2: Apply the Schema Overlay Migration

Run Alembic migrations to create the isolated `cas_*` tables on your PostgreSQL database:

```bash
cd backend
alembic upgrade head
```

#### Tables Created:
| Table Name | Description |
| :--- | :--- |
| `cas_users` | Reference identity credentials & roles (`admin`, `uploader`, `trainer`, `researcher`, `auditor`). |
| `cas_data_envelopes` | Encrypted envelope headers: object URIs, wrapped DEKs, KEK version, AAD metadata. |
| `cas_search_indexes` | Blind HMAC-SHA-256 tokens mapping searchable fields to envelope IDs. |
| `cas_policies` | Versioned Rego policy definitions tracked in the database. |
| `cas_ml_jobs` | Scoped ML jobs with expiration timestamps, requester IDs, and state machines. |
| `cas_job_manifests` | Cryptographically signed manifests binding approved envelope IDs to a job. |
| `cas_access_audit` | Append-only, HMAC-chained tamper-evident audit log. |
| `cas_anomaly_alerts` | Advisory alerts emitted by the IsolationForest anomaly detector. |
| `cas_key_versions` | History of KEK rotation metadata and rewrap statuses. |

---

### Step 3: Implement or Configure Pluggable Adapters

CAS-SE provides modular protocols for storage, key management, and identity:

#### 1. Storage Adapter (`StorageAdapter`)
To integrate a custom cloud backend, implement `app.adapters.storage.StorageAdapter`:
```python
from app.adapters.storage import StorageAdapter

class CustomS3Adapter(StorageAdapter):
    async def put_object(self, object_key: str, data: bytes) -> str:
        # Upload ciphertext blob to S3
        ...
    async def get_object(self, object_key: str) -> bytes:
        # Retrieve ciphertext blob from S3
        ...
    async def delete_object(self, object_key: str) -> bool:
        ...
    async def health_check(self) -> bool:
        ...
```

#### 2. Key Management Service (`KeyServiceAdapter`)
CAS-SE abstracts key wrapping (`wrap_dek` / `unwrap_dek`). To connect AWS KMS, HashiCorp Vault, or Google Cloud KMS:
```python
from app.adapters.key_service import KeyServiceAdapter

class VaultKeyService(KeyServiceAdapter):
    def get_current_kek(self) -> tuple[bytes, int]:
        # Fetch current transit key from Vault
        ...
    def get_kek_by_version(self, version: int) -> bytes:
        ...
    def rotate_kek(self) -> tuple[bytes, int]:
        ...
```

#### 3. Identity Adapter (`IdentityAdapter`)
To federate authentication with Okta, Azure AD, or Keycloak:
Implement `app.adapters.identity.IdentityAdapter` to map SAML/OIDC claims to CAS-SE roles:
- `admin`
- `uploader`
- `trainer`
- `researcher`
- `auditor`

---

### Step 4: Calling Ingestion and Protected Search APIs

#### Ingest Encrypted Records:
```bash
curl -X POST https://cas.internal/envelopes \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -F "file=@scan_001.png" \
  -F "dataset_id=rad-biopsy-2026" \
  -F "subject_id=patient-4091" \
  -F "sensitivity_label=restricted"
```
*Flow*:
1. Upload validated (magic bytes, size limits).
2. Fresh random 32-byte DEK generated via `os.urandom`.
3. Payload encrypted with AES-256-GCM + deterministic AAD.
4. DEK wrapped with KEK version 1.
5. Ciphertext written to MinIO/S3; metadata stored in `cas_data_envelopes`.
6. Blind equality index tokens written to `cas_search_indexes` via `HMAC-SHA-256`.
7. Audit event appended to hash chain.

#### Perform Protected Equality Search:
```bash
curl -X GET "https://cas.internal/search?field=subject_id&value=patient-4091" \
  -H "Authorization: Bearer <JWT_TOKEN>"
```
*Guarantees*: No plaintext search terms are logged or stored in the database. Tokens match using deterministic HMAC equality tokens.

---

### Step 5: Context-Aware Access & ML Job Execution

#### 1. Trainer requests ML job creation:
```bash
curl -X POST https://cas.internal/ml-jobs \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "purpose": "Train breast density classifier",
    "dataset_scope": "rad-biopsy-2026",
    "requested_view": "feature_only",
    "duration_hours": 24
  }'
```

#### 2. Admin reviews and approves job:
```bash
curl -X POST https://cas.internal/ml-jobs/<JOB_ID>/approve \
  -H "Authorization: Bearer <ADMIN_JWT>"
```
*Result*: Generates a cryptographically signed job manifest containing permitted envelope IDs, allowed view (`feature_only`), expiration timestamp, and HMAC signature.

#### 3. Requesting Record Data with Context-Aware Minimization:
```bash
curl -X POST https://cas.internal/access-request \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "envelope_id": "<ENVELOPE_UUID>",
    "purpose": "Train breast density classifier",
    "requested_view": "feature_only",
    "job_id": "<JOB_ID>"
  }'
```
*Decision Matrix*:
- **Trainer + Valid Job**: Permitted view `feature_only` (CNN embedding vector returned; raw image is NEVER released).
- **Trainer requesting `raw_image`**: **Denied** (403 Forbidden) and audited.
- **Expired Job**: **Denied** (403 Forbidden) and audited.
- **Researcher without Explicit Approval**: **Denied** (403 Forbidden).

---

## 3. Cryptographic and Audit Operations

### Wrapping Key (KEK) Rotation Without Re-encryption
When security policy mandates rotating the primary wrapping key:
```bash
curl -X POST https://cas.internal/keys/rotate \
  -H "Authorization: Bearer <ADMIN_JWT>"
```
*Mechanism*:
1. KEK version advances from $v$ to $v+1$.
2. Every envelope's DEK is unwrapped using $\text{KEK}_v$ and rewrapped with $\text{KEK}_{v+1}$.
3. Ciphertext in S3/MinIO **remains untouched**—no heavy I/O or multi-terabyte re-encryption required.
4. Operation is recorded in `cas_key_versions` and audited.

### Audit Chain Integrity Verification
Auditors independently verify the mathematical integrity of the append-only HMAC chain:
```bash
curl -X GET https://cas.internal/audit/verify \
  -H "Authorization: Bearer <AUDITOR_JWT>"
```
*Response*:
```json
{
  "is_valid": true,
  "message": "Audit chain intact -- 1482 events verified",
  "events_verified": 1482
}
```

### Anomaly Alerts Review
Auditors review suspicious patterns detected by the IsolationForest worker:
```bash
curl -X GET https://cas.internal/anomalies?reviewed=false \
  -H "Authorization: Bearer <AUDITOR_JWT>"
```

---

## 4. Troubleshooting and Production Checklist

- [ ] `OPA_URL` is responsive and network policies allow TCP connectivity from the API.
- [ ] Database user has DDL permissions for `alembic upgrade head`.
- [ ] Object storage credentials possess PutObject, GetObject, and DeleteObject permissions on the configured bucket.
- [ ] Secret environment variables (`CAS_KEK_V*`, `JWT_SECRET_KEY`, `INDEX_HMAC_KEY`, `AUDIT_INTEGRITY_KEY`) are generated using cryptographically secure random sources (`openssl rand -base64 32`).
- [ ] Celery worker and Redis are active for background feature extraction and model training.
