# Product Requirements Document: CAS-SE

## 1. Product Summary

**Product name:** CAS-SE (Context-Aware, Searchable, Split-Key Data Envelope)

**Product type:** Integrable data-governance architecture (middleware layer)

CAS-SE is a **privacy-preserving data-governance architecture** designed to be **integrated into an organization's existing database and storage infrastructure**. It is not a standalone application — it is a set of composable services, schema overlays, policy engines, and cryptographic primitives that wrap around an organization's existing data layer to enforce envelope encryption, context-aware access control, protected search, data minimization, and tamper-evident auditing for sensitive ML datasets.

An adopting organization installs CAS-SE as a middleware layer between their application tier and their database/storage tier. CAS-SE intercepts data ingestion, search, and access operations, applies cryptographic protections and policy evaluation, and delegates actual persistence to the organization's own PostgreSQL (or compatible) database and object storage (S3, MinIO, Azure Blob, GCS).

The project is an academic prototype built from established cryptographic primitives. It does not invent cryptography, provide absolute security, or replace a production KMS, HSM, or formal security review.

---

## 2. Problem Statement

Organizations that run ML workloads on sensitive datasets (medical records, financial data, proprietary research, biometric data) face a fundamental tension:

- **Encryption at rest** protects stolen storage but does nothing to control what an authorized user can see or do once access is granted.
- **Role-based access control** gives users broad, long-lived permissions with no contextual evaluation.
- **Plaintext indexes** expose sensitive identifiers to anyone with database access.
- **Audit logs** can be modified, deleted, or can themselves leak sensitive metadata.

These organizations already have production databases, storage systems, and application layers. They need a **drop-in governance layer** — not a replacement database — that enforces least privilege for every data access operation by evaluating the authenticated identity, role, purpose, requested data view, dataset scope, ML-job state, policy version, and expiration time.

CAS-SE is that governance layer.

---

## 3. Architecture Vision: Integration, Not Replacement

### 3.1 What CAS-SE Is

CAS-SE is a **middleware architecture** that:

- **Wraps** the organization's existing database with additional schema tables (envelopes, protected indexes, audit chain, policies, key versions).
- **Intercepts** data ingestion to encrypt payloads before they reach storage.
- **Replaces** plaintext search indexes with HMAC-based equality tokens.
- **Evaluates** every data access request against context-aware OPA policies before releasing data.
- **Minimizes** the data view returned based on the requester's role, purpose, job state, and policy decision.
- **Chains** every operation into a tamper-evident HMAC audit trail.

### 3.2 What CAS-SE Is Not

- It is **not a standalone database** — it sits atop the organization's existing PostgreSQL (or compatible RDBMS).
- It is **not a standalone object store** — it delegates encrypted blob storage to the organization's existing S3-compatible store (MinIO, AWS S3, Azure Blob, GCS).
- It is **not a complete application** — it provides API endpoints and services that the organization's own application layer consumes.
- It is **not a KMS/HSM** — it provides an envelope-encryption abstraction that the organization plugs their own key management backend into.

### 3.3 Integration Model

```
┌──────────────────────────────────────────────────────────────┐
│                  ORGANIZATION'S APPLICATION LAYER            │
│              (their existing web app, ML pipeline, etc.)     │
└─────────────────────────┬────────────────────────────────────┘
                          │  REST API calls
                          ▼
┌──────────────────────────────────────────────────────────────┐
│                     CAS-SE MIDDLEWARE LAYER                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐   │
│  │ Envelope │ │ Policy   │ │  Audit   │ │     Key       │   │
│  │ Service  │ │ Engine   │ │ Service  │ │   Service     │   │
│  │          │ │  (OPA)   │ │ (Chain)  │ │  (Envelope    │   │
│  │ encrypt, │ │ context- │ │ tamper-  │ │  encryption,  │   │
│  │ decrypt, │ │ aware    │ │ evident  │ │  rotation,    │   │
│  │ search,  │ │ ABAC     │ │ HMAC     │ │  split-key)   │   │
│  │ minimize │ │          │ │ chain    │ │               │   │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └───────┬───────┘   │
│       │             │            │                │           │
│  ┌────┴─────────────┴────────────┴────────────────┴───────┐  │
│  │              DATABASE ADAPTER INTERFACE                 │  │
│  │     (SQLAlchemy-based — works with any supported DB)    │  │
│  └────┬───────────────────────────────────────────┬───────┘  │
└───────┼───────────────────────────────────────────┼──────────┘
        │                                           │
        ▼                                           ▼
┌───────────────────┐                 ┌──────────────────────┐
│  ORGANIZATION'S   │                 │   ORGANIZATION'S     │
│  PostgreSQL /     │                 │   Object Storage     │
│  Compatible RDBMS │                 │   (MinIO/S3/Azure/   │
│                   │                 │    GCS)              │
└───────────────────┘                 └──────────────────────┘
```

---

## 4. Goals

1. Provide a **schema overlay** that organizations apply to their existing database to store encrypted envelopes, protected indexes, policies, audit chains, and key versions alongside their existing tables.
2. Encrypt every ingested data record independently using AES-256-GCM before it reaches the organization's storage.
3. Store encrypted payloads in the organization's own object storage — never as raw blobs in the RDBMS.
4. Permit approved equality search through HMAC-SHA-256 protected tokens — without storing searchable values in plaintext.
5. Evaluate every data access request against deny-by-default, purpose-aware, context-aware OPA policies.
6. Return a minimized data view (metadata, masked image, feature vector, or raw image) based on the policy decision.
7. Bind data access to approved, scoped, expiring ML jobs.
8. Produce a hash-chained, tamper-evident audit trail for every data operation.
9. Support wrapping-key rotation without re-encrypting stored payloads.
10. Provide adapter interfaces so organizations can plug in their own KMS, storage backend, and identity provider.
11. Evaluate privacy, performance, and ML utility against plaintext and encrypted-RBAC baselines.
12. Detect suspicious access patterns from audit logs using anomaly detection.

---

## 5. Non-Goals

- Inventing encryption, searchable encryption, key sharing, or password hashing algorithms.
- Claiming protection against a fully compromised trusted training environment.
- Preventing misuse after a user is legitimately given raw data.
- Processing real biometric, face, palm-print, health, personally identifiable, or institutionally restricted datasets.
- Providing a production-grade HSM, KMS, confidential-computing environment, or immutable audit store.
- Replacing the organization's existing database engine, identity provider, or application framework.
- Supporting arbitrary encrypted range, fuzzy, semantic, or vector search in the first release.

---

## 6. Integration Personas

These are the roles within an adopting organization that interact with CAS-SE:

### 6.1 Integration Roles (Organizational Staff)

| Role | Responsibility | CAS-SE Integration Point |
| --- | --- | --- |
| **Platform Engineer** | Deploys CAS-SE middleware alongside existing infrastructure | Configures database adapter, object storage adapter, OPA deployment, key service backend |
| **DBA / Data Engineer** | Manages the organization's database | Applies CAS-SE schema overlay migrations to existing PostgreSQL; monitors CAS-SE tables |
| **Security Architect** | Defines access policies and key management strategy | Writes OPA/Rego policies; configures KEK source (KMS/Vault/HSM); reviews audit chain |
| **Application Developer** | Builds the organization's ML platform or data pipeline | Integrates CAS-SE REST API into their application; calls envelope, search, and access-request endpoints |

### 6.2 End-User Roles (Data Users Within the Organization)

| Role | Primary Capability | Restrictions |
| --- | --- | --- |
| Admin | Manages policies, approves ML jobs | All sensitive actions audited; does not bypass policy by default |
| Uploader | Uploads dataset records through the organization's app | Cannot read raw records by default |
| Trainer | Creates ML jobs and trains models | Receives only policy-approved views for active approved jobs |
| Researcher | Requests data for approved research tasks | Raw access requires explicit approval and an active scoped job |
| Auditor | Reviews access events and anomalies | Cannot decrypt data or access image payloads |

---

## 7. Core User Stories

### Integration Stories

- As a **platform engineer**, I can deploy CAS-SE as a middleware layer connected to our existing PostgreSQL database and S3-compatible object store.
- As a **DBA**, I can apply CAS-SE schema migrations to our existing database without disrupting our current tables.
- As a **security architect**, I can write custom OPA/Rego policies that reflect our organization's specific data governance requirements.
- As an **application developer**, I can call CAS-SE REST API endpoints from our existing ML platform to encrypt uploads, search records, and request data access.
- As a **platform engineer**, I can configure CAS-SE to use our organization's KMS (e.g., AWS KMS, HashiCorp Vault) as the KEK backend.

### End-User Stories

- As an uploader, I can upload a valid dataset record through our platform, and CAS-SE encrypts it before it reaches storage.
- As a trainer, I can request a time-limited ML job for a specific dataset scope.
- As an admin, I can approve or reject a training or research job.
- As a trainer with an active approved job, I receive feature vectors rather than raw images.
- As a researcher with explicit approval, I can receive a raw image only when the policy allows it.
- As an auditor, I can filter audit events, verify the audit chain, and review anomaly alerts.
- As an admin, I can rotate the wrapping key without re-encrypting all encrypted image payloads.
- As a project evaluator, I can compare security overhead and ML performance across three system designs.

---

## 8. Functional Requirements

### 8.1 Schema Overlay (Database Integration)

CAS-SE adds the following tables to the organization's existing database. These tables are managed through Alembic migrations and do not modify or conflict with the organization's existing schema.

**CAS-SE tables (added to the organization's database):**

- `cas_users` — CAS-SE identity records (can federate with the organization's existing user table via a foreign key or adapter)
- `cas_refresh_tokens` — Session management for CAS-SE API access
- `cas_data_envelopes` — Encrypted envelope metadata (nonce, wrapped DEK, ciphertext hash, object URI, sensitivity label)
- `cas_protected_indexes` — HMAC-SHA-256 equality-search tokens
- `cas_policies` — Access policy definitions
- `cas_policy_versions` — Versioned policy snapshots
- `cas_access_audit` — Hash-chained tamper-evident audit events
- `cas_ml_jobs` — ML job requests with scope, purpose, and expiry
- `cas_job_approvals` — Admin approval/rejection records
- `cas_anomaly_alerts` — IsolationForest anomaly detection alerts
- `cas_key_versions` — KEK version tracking for rotation

**Key constraints:**

- Use UUID primary keys for all CAS-SE resources.
- Store all timestamps as `TIMESTAMPTZ` in UTC.
- Unique index on `cas_protected_indexes(field_name, token_version, hmac_token, envelope_id)`.
- Lookup indexes on audit actor/time, audit envelope/time, audit decision/time, and ML-job status/expiry.
- Foreign keys between envelopes, policies, jobs, approvals, and audit events.
- All schema changes managed through Alembic migrations — never through application startup DDL.

### 8.2 Storage Adapter Interface

CAS-SE stores encrypted ciphertext blobs in the organization's object storage. The storage adapter interface abstracts the backend:

```python
class StorageAdapter(Protocol):
    def put_object(self, key: str, data: bytes) -> str: ...
    def get_object(self, key: str) -> bytes: ...
    def delete_object(self, key: str) -> None: ...
    def health_check(self) -> bool: ...
```

**Provided adapters:**

- `MinIOAdapter` — Default reference adapter using boto3/S3 API
- `LocalFileAdapter` — Fallback for development/testing
- Organizations implement their own adapter for Azure Blob, GCS, or custom storage

### 8.3 Key Service Interface

CAS-SE provides an envelope-encryption abstraction with a pluggable KEK backend:

```python
class KeyServiceAdapter(Protocol):
    def get_current_kek(self) -> tuple[bytes, int]: ...  # (key, version)
    def get_kek_by_version(self, version: int) -> bytes: ...
    def rotate_kek(self) -> tuple[bytes, int]: ...  # new (key, version)
```

**Provided implementations:**

- `EnvVarKeyService` — Reads KEK from environment variable (development/demo)
- `SplitKeyService` — Simulated 2-of-3 Shamir secret sharing (academic demonstration)
- Organizations implement their own adapter for AWS KMS, HashiCorp Vault, or HSM

### 8.4 Identity Federation Interface

CAS-SE can operate with its own user table or federate with the organization's existing identity system:

```python
class IdentityAdapter(Protocol):
    def resolve_user(self, token: str) -> CASUser: ...
    def get_user_role(self, user_id: UUID) -> str: ...
```

**Provided implementations:**

- `BuiltInIdentity` — CAS-SE's own JWT/Argon2 auth (reference implementation)
- Organizations implement their own adapter for LDAP, OIDC, SAML, or existing user tables

### 8.5 Authentication and Session Management (Reference Implementation)

- Registration, login, logout, token refresh, and current-user endpoints.
- Argon2 password hashing via `pwdlib[argon2]`.
- Short-lived JWT access tokens and refresh-token rotation.
- Secure refresh-token storage and revocation on logout.
- Identity and role resolved from verified JWT and server-side authorization data.
- Never trust client-supplied `user_id`, `role`, permissions, approval status, or timestamps.
- Rate-limit login and sensitive access-request endpoints.

### 8.6 Encrypted Record Ingestion

- Validate upload file size, extension, MIME type, and image decodability before storage.
- Generate a fresh random 32-byte Data Encryption Key (DEK) for every uploaded record.
- Encrypt each payload using AES-256-GCM with a unique random 12-byte nonce.
- Use AES-GCM authenticated associated data (AAD) containing `envelope_id`, `policy_id`, `sensitivity_label`, and `encryption_version`.
- Store ciphertext only in the organization's object storage (via storage adapter).
- Store envelope metadata in the organization's database (via schema overlay) — never raw data bytes.
- Create HMAC-SHA-256 protected tokens for approved equality-search fields (initially `dataset_id` and `class_label`).
- Create an audit event for every successful or failed upload attempt.

### 8.7 Protected Search

- Normalize permitted search values before token generation.
- Compute `HMAC-SHA-256(index_key, normalized_value)` for equality search.
- Store protected tokens as `BYTEA` values with a token version.
- Search only approved tokenized fields.
- Filter search results through the access policy before returning.
- Return only permitted metadata and envelope IDs — never HMAC tokens, raw identifiers, keys, or encrypted DEKs.
- Document equality-pattern leakage as a known limitation.

### 8.8 Context-Aware Access Control

- Use Open Policy Agent (OPA) and Rego policies for sensitive access decisions.
- Deny access by default when context is incomplete, the policy engine is unavailable, the job is expired, or policy evaluation fails.
- Evaluate: authenticated identity, role, purpose, requested view, resource sensitivity, dataset scope, policy version, job approval, job status, and expiry.
- Produce structured policy results: decision, reason, policy ID, policy version, allowed view, and decision expiry.

**Supported decisions:**

| Decision | Data Returned |
| --- | --- |
| `deny` | Nothing — access refused |
| `metadata_only` | Explicitly approved non-sensitive metadata |
| `masked_image` | Derived blurred or low-resolution image with no direct identifiers |
| `feature_only` | Approved image embedding or feature vector |
| `raw_image` | Decrypted original — only when explicit policy permits |

### 8.9 ML Job Workflow

- Trainers and researchers create scoped ML/research job requests.
- Jobs contain: requester, purpose, dataset scope, requested view, status, approval ID, policy version, creation time, and expiration time.
- Admins approve, reject, or cancel jobs.
- Approved jobs produce a short-lived signed manifest containing permitted envelope IDs, allowed view, expiry, policy version, and job ID.
- Background workers run feature extraction and model-training jobs.
- A training worker may consume only the records and data views included in its active job manifest.
- Every job action and per-record release is audited.

### 8.10 Key Management and Rotation

- Envelope encryption: encrypt payloads with DEKs and protect DEKs through a versioned KEK abstraction.
- Wrapping-key rotation: rewrap DEKs without re-encrypting stored payload ciphertext.
- Simulated 2-of-3 split-key recovery using a vetted dependency only.
- Key shares kept separated; independent authorization required in the simulation.
- Single share cannot recover protected key material.
- Split-key feature is clearly documented as an academic simulation — not a replacement for production KMS, Vault, or HSM.

### 8.11 Audit and Anomaly Detection

- Append-only audit events for: login, logout, upload, search, access request, allow, deny, decryption, job creation/approval/rejection/cancellation, policy changes, key rotation, and anomaly alerts.
- Canonicalize audit fields before calculating hashes.
- Chain records using a dedicated audit integrity key and HMAC-SHA-256.
- Audit-chain verification and signed checkpoint export.
- IsolationForest-based anomaly detection over audit features.
- Alerts for: unusual access volume, denied-request spikes, raw-data requests, unusual access times, job failures, excessive dataset diversity.
- Anomaly detection may flag activity or require review — it never grants access automatically.

---

## 9. Required Policy Rules

- Uploader can upload records but cannot read raw records by default.
- Trainer receives feature-only data only for an active, approved, unexpired ML job with matching dataset scope.
- Trainer raw-image requests are denied.
- Researcher raw-image requests require an active explicitly approved research job.
- Auditor can view audit records and anomaly alerts but cannot decrypt payloads.
- Admin can manage policies and job approvals; all actions are audited.
- Expired, rejected, cancelled, or scope-mismatched jobs deny access.
- Debugging requests return masked output only and omit direct identifiers.
- OPA unavailability results in denial for sensitive operations.

---

## 10. Technical Architecture

### 10.1 CAS-SE Middleware Components

| Component | Responsibility | Deployment |
| --- | --- | --- |
| **CAS-SE API** (FastAPI) | Authentication, validation, orchestration, REST API endpoints | Container or process alongside the org's app |
| **OPA** | Context-aware policy evaluation via Rego | Sidecar container or shared OPA instance |
| **Worker** | Feature extraction, ML jobs, benchmarks, anomaly detection | Background process with Redis broker |

### 10.2 Organization-Provided Infrastructure (Plugged In)

| Infrastructure | Requirement | Adapter |
| --- | --- | --- |
| **RDBMS** | PostgreSQL 14+ (or compatible) | SQLAlchemy database adapter |
| **Object Storage** | S3-compatible (MinIO, AWS S3, Azure Blob, GCS) | Storage adapter interface |
| **Key Management** | KEK source (env var, KMS, Vault, HSM) | Key service adapter |
| **Identity** | User identity source (built-in, LDAP, OIDC, SAML) | Identity adapter |
| **Redis** | Worker broker and task coordination | Standard Redis connection |

### 10.3 Backend Module Structure

```text
backend/app/
  api/              # REST API route handlers
  core/             # Configuration, security utilities
  db/               # Database connection, base model
  models/           # SQLAlchemy ORM models (schema overlay)
  schemas/          # Pydantic request/response schemas
  services/         # Core business logic
    crypto.py       # AES-GCM, HMAC, DEK/KEK operations
    envelope.py     # Encrypted ingestion, decryption, minimization
    audit.py        # Hash-chained audit trail
    key_management.py  # Split-key simulation, rotation
  adapters/         # Pluggable backend adapters
    storage.py      # StorageAdapter implementations
    identity.py     # IdentityAdapter implementations
    key_service.py  # KeyServiceAdapter implementations
  policy/           # OPA integration, Rego policy management
  workers/          # Celery/RQ async task workers
  tests/            # Unit and integration tests
```

---

## 11. Integration Guide: How an Organization Adopts CAS-SE

### Step 1: Deploy CAS-SE Alongside Existing Infrastructure

```yaml
# The organization adds CAS-SE containers to their existing docker-compose or k8s
services:
  cas-se-api:
    image: cas-se/api:latest
    environment:
      DATABASE_URL: postgresql://user:pass@org-postgres:5432/org_database
      OBJECT_STORAGE_ENDPOINT: https://org-minio.internal:9000
      OPA_URL: http://cas-se-opa:8181
      KEK_SOURCE: aws-kms  # or vault, env, hsm
      # ... organization's existing credentials
  cas-se-opa:
    image: openpolicyagent/opa:latest
    volumes:
      - ./opa/policies:/policies
  cas-se-worker:
    image: cas-se/worker:latest
    # ... connects to org's Redis and database
```

### Step 2: Apply Schema Overlay Migrations

```bash
# Run CAS-SE Alembic migrations against the organization's database
# This adds cas_* tables without touching existing tables
alembic -c cas_se_alembic.ini upgrade head
```

### Step 3: Configure Adapters

```python
# The organization configures which adapters CAS-SE uses
CAS_SE_CONFIG = {
    "storage_adapter": "MinIOAdapter",       # or "AzureBlobAdapter", "GCSAdapter"
    "key_service_adapter": "AWSKMSAdapter",  # or "VaultAdapter", "EnvVarKeyService"
    "identity_adapter": "OIDCAdapter",       # or "BuiltInIdentity", "LDAPAdapter"
}
```

### Step 4: Write Organization-Specific OPA Policies

```rego
# Organization writes Rego policies reflecting their governance rules
package cas_se.access

default allow = false

allow {
    input.role == "ml_engineer"
    input.purpose == "model_training"
    input.job.status == "approved"
    input.job.expires_at > time.now_ns()
    input.requested_view == "feature_only"
}
```

### Step 5: Integrate CAS-SE API into the Organization's Application

```python
# Organization's ML platform calls CAS-SE API
import httpx

# Upload encrypted record
response = httpx.post("http://cas-se-api:8000/envelopes", ...)

# Search with protected tokens
results = httpx.post("http://cas-se-api:8000/search", json={
    "field_name": "dataset_id",
    "value": "chest-xray-2024"
})

# Request access with context
access = httpx.post("http://cas-se-api:8000/access-request", json={
    "envelope_id": "...",
    "purpose": "model_training",
    "requested_view": "feature_only",
    "job_id": "..."
})
```

---

## 12. API Requirements

### Authentication (Reference Implementation)

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /auth/me`

### Envelopes and Search

- `POST /envelopes` — Encrypt and ingest a data record
- `GET /envelopes` — List envelope metadata (policy-filtered)
- `GET /envelopes/{envelope_id}` — Get envelope metadata
- `POST /search` — Protected equality search via HMAC tokens
- `POST /access-request` — Request data access with context evaluation

### ML Jobs

- `POST /ml-jobs` — Create a scoped ML/research job request
- `GET /ml-jobs` — List jobs
- `GET /ml-jobs/{job_id}` — Get job details
- `POST /ml-jobs/{job_id}/approve` — Admin approves job
- `POST /ml-jobs/{job_id}/reject` — Admin rejects job
- `POST /ml-jobs/{job_id}/cancel` — Cancel job
- `GET /ml-jobs/{job_id}/results` — Get job results

### Governance

- `GET /audit` — Query audit trail
- `GET /audit/verify` — Verify audit chain integrity
- `GET /anomalies` — List anomaly alerts
- `POST /policies` — Create/update policy
- `GET /policies` — List active policies
- `POST /keys/rotate` — Rotate wrapping key
- `GET /health` — Service health check
- `GET /metrics` — Operational metrics

All sensitive endpoints require JWT validation, role checks, OPA evaluation, and structured audit logging.

---

## 13. Reference Frontend (Demonstration Dashboard)

CAS-SE ships with a reference React + TypeScript dashboard to demonstrate and validate integration. **This is not part of the architecture itself** — it is a reference implementation showing how an organization's frontend would interact with CAS-SE APIs.

### Reference Dashboard Pages

- Login and registration (reference identity flow)
- Main dashboard: active jobs, access decisions, audit status, anomaly summary
- Secure upload form
- Protected search interface
- Record access-request interface (displays decision reason and permitted view)
- Trainer ML-job creation and status page
- Admin approval queue
- Policy viewer and manager
- Filterable audit viewer
- Audit-chain verification page
- Anomaly alerts page
- Privacy-utility experiment dashboard with charts
- System health page

### Design Requirements

- The reference UI implements a "Double-Bezel" high-end design aesthetic.
- Avoid generic styling. Prioritize premium visual excellence with modern typography, subtle micro-animations, and dynamic layout interactions.

The frontend never displays keys, encrypted DEKs, HMAC tokens, raw audit integrity values, or storage credentials.

---

## 14. ML and Evaluation Requirements

Use Fashion-MNIST or CIFAR-10 as the default demonstration dataset.

### Required Experiments

| Baseline | Description |
| --- | --- |
| **Plaintext** | Normal image access and training — no encryption or policy enforcement |
| **Encrypted-RBAC** | Encrypted records with role-only access control |
| **CAS-SE** | Encrypted records + protected search + context-aware policy + job scoping + minimized views + auditing |

### Metrics

- Upload/encryption latency
- Protected-search latency
- Access-decision and data-release latency
- Storage overhead
- Accuracy, precision, recall, and F1 score
- Training duration
- Percentage of unauthorized access requests denied
- Number of raw-data releases avoided through minimized views
- Ciphertext and audit-tampering detection
- Single-share compromise behaviour

Visualize privacy versus utility using charts comparing raw image, low-resolution/masked image, and feature-vector workflows.

---

## 15. Security Requirements

- Argon2 password hashing.
- Short-lived JWT access tokens and refresh-token rotation.
- Server-generated UTC timestamps.
- CORS restrictions configurable through environment variables.
- Upload validation, request-size limits, and rate limits.
- Object storage buckets kept private; randomized object keys.
- No plaintext image payloads stored in the RDBMS.
- No raw records exposed through static URLs.
- No secrets written to logs, exceptions, frontend state, or API responses.
- TLS in any non-local deployment; local-development limitations documented.
- Dependency scanning, linting, and CI security scanning.
- OPA errors or key-service errors treated as deny conditions for sensitive reads.

---

## 16. Testing Requirements

### Backend Tests

- Valid AES-GCM encryption and decryption.
- Authentication failure after ciphertext modification.
- Detection of ciphertext swapping through AAD.
- Prevention of role impersonation through request-body values.
- Password hashing and safe response serialization.
- Refresh-token rotation and logout revocation.
- Protected-search operation without plaintext index values.
- Trainer feature-only access for an approved active job.
- Trainer denial for raw-image access.
- Researcher raw-data access only after explicit approval.
- Expired and scope-mismatched job denial.
- Audit-chain verification before and after tampering.
- Key rewrapping without payload re-encryption.
- Single-share failure and threshold recovery in the split-key simulation.
- Denial when OPA is unavailable.
- Rate limiting for login and access-request endpoints.
- **Storage adapter interface tests** (verify pluggable adapters work correctly).
- **Schema overlay isolation tests** (verify CAS-SE migrations don't conflict with existing tables).

### Frontend Tests (Reference Dashboard)

- Login.
- Secure upload.
- ML-job creation and admin approval.
- Denied trainer raw-data request.
- Audit verification.

---

## 17. Delivery Plan

### Phase 1: Architecture Foundation and Adapter Interfaces

- Define storage adapter, key service adapter, and identity adapter interfaces.
- Create repository structure.
- Set up Docker Compose for CAS-SE API, worker, OPA, and reference infrastructure (PostgreSQL, MinIO, Redis).
- Environment configuration, health checks, linting, CI, and initial documentation.

### Phase 2: Schema Overlay and Identity Layer

- Build CAS-SE database models (schema overlay tables).
- Create Alembic migration scripts that add CAS-SE tables to an existing database.
- Implement reference authentication (JWT, refresh tokens, Argon2).
- Implement identity adapter interface for federation with external identity providers.
- Seed demo users.

### Phase 3: Encrypted Envelope Ingestion

- Build encrypted upload pipeline.
- Implement storage adapter interface and MinIO reference adapter.
- Envelope metadata persistence, HMAC indexing, unit tests.

### Phase 4: Authorization and Data Views

- Build OPA integration, Rego policies, protected search, access requests, minimized data views, and audit events.

### Phase 5: ML Jobs and Background Processing

- Job creation, approval, expiration, signed manifests, worker execution, feature extraction, result storage.

### Phase 6: Audit and Key Lifecycle

- Hash-chained audit verification, checkpoints, KEK rotation via key service adapter, split-key simulation.

### Phase 7: ML Evaluation and Detection

- Baseline classifier, privacy-utility experiments, benchmark scripts, charts, audit anomaly detection.

### Phase 8: Reference Dashboard and Documentation

- Complete reference React dashboard, Playwright tests, Docker verification, integration guide, documentation, demo data, and demonstration flow.

---

## 18. Definition of Done

- `docker compose up --build` starts all CAS-SE middleware services and reference infrastructure.
- CAS-SE schema overlay migrations apply cleanly to a fresh PostgreSQL database.
- A user can register, authenticate, and use role-appropriate features through the CAS-SE API.
- An uploader can upload an encrypted record; the RDBMS contains no raw image payloads.
- Object storage stores ciphertext, not plaintext images.
- Protected HMAC equality search returns authorized records only.
- A trainer with an approved active job receives feature-only data.
- A trainer requesting raw data is denied and audited.
- An explicitly approved researcher can access permitted raw data.
- Audit-chain verification detects tampered records.
- KEK rotation rewraps DEKs without payload re-encryption.
- Storage adapter interface works with at least MinIO and local-file backends.
- ML privacy-utility results are generated and visible in the reference dashboard.
- Audit anomaly alerts are generated from stored audit data.
- Backend tests, frontend tests, linting, and CI checks pass.
- Integration guide documents how an organization connects CAS-SE to their existing database and storage.

---

## 19. Known Limitations and Ethics

- HMAC equality tokens reveal whether indexed values are equal (equality-pattern leakage).
- Derived feature vectors can still contain identity or sensitive information.
- A valid user can misuse data after legitimate release.
- A database-only hash chain is tamper-evident but not independently immutable.
- The split-key workflow is a prototype simulation, not a hardware-backed key-management system.
- The prototype does not protect against a fully compromised trusted training environment.
- Only public, synthetic, or approved non-sensitive datasets may be used in development, screenshots, tests, and demonstrations.
- CAS-SE is an academic prototype architecture — organizations must conduct their own security review, threat modeling, and compliance assessment before production use.
