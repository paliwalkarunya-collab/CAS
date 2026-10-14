# CAS-SE Architecture Documentation

## 1. Architectural Philosophy

CAS-SE (**Context-Aware, Searchable, Split-Key Data Envelope**) is engineered as a **data-governance middleware layer**. It is neither a new database nor a replacement object store. Instead, it is inserted into the data access path between an organization's existing application services and its underlying storage tier.

### The Problem It Solves
Traditional enterprise architectures rely on:
1. **Static encryption at rest**: Encrypts disks or tables, but once an authorized identity connects, the entire dataset is accessible in plaintext.
2. **Coarse Role-Based Access Control (RBAC)**: Grants permissions based on identity alone without assessing purpose, job state, expiry, or required data granularity.
3. **Plaintext Search Indices**: Exposes sensitive labels or identifiers to database administrators and SQL injection risks.
4. **Vulnerable Audit Logs**: System logs can be selectively truncated or modified to hide unauthorized queries.

### The CAS-SE Solution
- **Independent Record Encryption**: Each uploaded record is encrypted with an isolated 32-byte Data Encryption Key (DEK) via AES-256-GCM.
- **Envelope Key Hierarchy**: DEKs are wrapped with a versioned Key Encryption Key (KEK).
- **HMAC Equality Search**: Equality indices store HMAC-SHA-256 digests rather than plaintext strings.
- **Fail-Closed Context-Aware Authorization**: Open Policy Agent (OPA) evaluates requester identity, role, purpose, dataset scope, and job approval status. If OPA is unreachable or context is missing, access is denied.
- **Dynamic Data Minimization**: Users only receive the data view permitted by policy (`metadata_only`, `masked_image`, `feature_only`, or `raw_image`).
- **Cryptographic Audit Hash-Chain**: Every access and lifecycle event is appended to an HMAC-chained audit log where any retroactive tampering breaks subsequent HMAC calculations.

---

## 2. Component Structure

| Component | Technology | Role |
| :--- | :--- | :--- |
| **CAS-SE API** | FastAPI / Python 3.13 | REST endpoints for ingestion, search, job management, access requests, and audit queries. |
| **Policy Engine** | Open Policy Agent (OPA) / Rego | Decoupled context-aware policy engine making allow/deny and data-view decisions. |
| **Worker Engine** | Celery + Redis | Asynchronous background processing for embeddings, model training, and anomaly detection. |
| **Schema Overlay** | SQLAlchemy + Alembic | Managed `cas_*` database tables coexisting within the organization's existing PostgreSQL database. |
| **Object Storage** | S3-compatible (MinIO/AWS S3) | Stores ciphertext blobs under non-enumerable, randomized keys. |

---

## 3. Data Flow

### 3.1 Ingestion Pipeline
1. Application calls `POST /envelopes` with raw payload and metadata (e.g. `dataset_id`, `class_label`).
2. Middleware validates MIME type, file size, and image integrity.
3. Middleware generates a fresh random 32-byte DEK and 12-byte nonce.
4. Payload is encrypted using AES-256-GCM with Authenticated Associated Data (AAD: `envelope_id`, `policy_id`, `sensitivity_label`, `encryption_version`).
5. Ciphertext blob is stored in object storage under an opaque random key.
6. The DEK is wrapped using the current KEK version.
7. Searchable fields are hashed with HMAC-SHA-256 and stored in `cas_protected_indexes`.
8. Metadata and wrapped DEK are committed to `cas_data_envelopes`.
9. An append-only audit record is added to `cas_access_audit`.

### 3.2 Access Request Pipeline
1. Application calls `POST /access-request` providing `envelope_id`, `purpose`, `requested_view`, and optional `job_id`.
2. Middleware verifies JWT, resolves user role from database (never from unverified token claim).
3. Context payload is sent to OPA (`cas_se/access`).
4. If OPA responds with `allow=true` and a permitted view:
   - Ciphertext blob is retrieved from object storage.
   - DEK is unwrapped using the KEK version recorded in the envelope.
   - Payload is decrypted and validated via AES-256-GCM auth tag.
   - Payload is minimized according to policy (e.g., extracted feature vector or blurred image).
   - Operation is logged to the HMAC audit chain.
   - Minimized data is returned to caller.
5. If OPA responds with `allow=false` or fails to respond:
   - Request is immediately rejected with HTTP 403.
   - Denial is recorded in the audit log.
