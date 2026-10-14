# CAS-SE Build Sequence

> **CAS-SE** — Context-Aware, Searchable, Split-Key Data Envelope  
> **Type:** Privacy-preserving data-governance middleware architecture  
> **Not a web app** — a cryptographic middleware layer that wraps an organization's existing database and object storage.

---

## Phase Overview

| Phase | Name | Status |
|-------|------|--------|
| 1 | Architecture Foundation & Adapter Interfaces | ✅ Complete |
| 2 | Schema Overlay & Identity Layer | ✅ Complete |
| 3 | Encrypted Envelope Ingestion | ✅ Complete |
| 4 | Authorization & Data Views | ✅ Complete |
| 5 | ML Jobs & Background Processing | ✅ Complete |
| 6 | Audit & Key Lifecycle | ✅ Complete |
| 7 | ML Evaluation & Anomaly Detection | ✅ Complete |
| 8 | Reference Dashboard & Documentation | ✅ Complete |

---

## Phase 1 — Architecture Foundation & Adapter Interfaces

**Goal:** Stand up the skeleton, define all adapter contracts, wire up Docker Compose, verify quality gates.

### Status: ✅ Complete (Verified with 21 passing automated tests, Ruff clean, full documentation)

### Completed Tasks
- [x] 1.1 Create repository directory structure (`backend/`, `opa/`, `docker/`, `docs/`)
- [x] 1.2 Define `StorageAdapter` Protocol (`adapters/storage.py`)
- [x] 1.3 Define `KeyServiceAdapter` Protocol (`adapters/key_service.py`)
- [x] 1.4 Define `IdentityAdapter` Protocol (`adapters/identity.py`)
- [x] 1.5 Implement `LocalFileAdapter` (dev/test fallback for storage with traversal checks)
- [x] 1.6 Implement `EnvVarKeyService` (dev KEK from environment variable with version tracking) and pure Python Shamir `SplitKeyService`
- [x] 1.7 Core configuration (`core/config.py`) — environment-variable driven via Pydantic Settings
- [x] 1.8 FastAPI application factory (`main.py`) with health endpoint (`GET /health`, `GET /metrics`)
- [x] 1.9 Docker Compose — CAS-SE API, OPA, Worker, PostgreSQL, MinIO, Redis (`docker-compose.yml`)
- [x] 1.10 Linting (`ruff`), type-checking (`mypy`), `.env.example`
- [x] 1.11 Initial CI configuration (GitHub Actions `.github/workflows/ci.yml`)
- [x] 1.12 `README.md` — integration overview and architecture guides (`docs/architecture.md`, `docs/adapters.md`, `docker/README.md`)
- [x] 1.13 Automated test suite for Phase 1 components (`tests/test_storage_adapters.py`, `tests/test_key_service_adapters.py`, `tests/test_identity_adapter.py`, `tests/test_config_and_health.py`) — **21/21 passing**.

---

## Phase 2 — Schema Overlay & Identity Layer

**Goal:** Add CAS-SE tables to the organization's database via Alembic migrations. Build reference identity and authentication layer.

### Status: ✅ Complete (Verified with 31 passing automated tests, Alembic migration upgrade/downgrade, demo seed script)

### Completed Tasks
- [x] 2.1 Async database engine & session factory (`app/db/session.py`) supporting both PostgreSQL (`asyncpg`) and SQLite (`aiosqlite`).
- [x] 2.2 ORM models for Users & Sessions (`cas_users`, `cas_refresh_tokens` in `app/models/models.py`).
- [x] 2.3 ORM models for Envelopes & Protected Indexes (`cas_data_envelopes`, `cas_protected_indexes` with unique composite index).
- [x] 2.4 ORM models for Policies & Versions (`cas_policies`, `cas_policy_versions`).
- [x] 2.5 ORM models for Audit & ML Jobs (`cas_access_audit`, `cas_ml_jobs`, `cas_job_approvals`).
- [x] 2.6 ORM models for Anomaly Detection & Key Lifecycle (`cas_anomaly_alerts`, `cas_key_versions`).
- [x] 2.7 Initial Alembic Schema Overlay Migration (`alembic/versions/001_initial_cas_overlay.py`) creating all 11 `cas_*` tables, tested for clean upgrade and downgrade.
- [x] 2.8 Built-in Identity Adapter (`BuiltInIdentity` in `app/services/identity_service.py`) adhering to `IdentityAdapter` Protocol, Argon2 password hashing, short-lived JWTs (HS256), and refresh-token rotation.
- [x] 2.9 Authentication API routes (`app/api/auth.py`): `POST /auth/register`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `GET /auth/me`.
- [x] 2.10 Demo seed script (`scripts/seed_demo_data.py`) creating default accounts for all 5 roles (`admin`, `uploader`, `trainer`, `researcher`, `auditor`).
- [x] 2.11 Automated test suite for Phase 2:
  - `tests/test_auth.py` (password hashing, JWT issuance & decoding, expired/tampered rejection, register, login, refresh rotation, logout revocation, `/auth/me`).
  - `tests/test_schema_overlay.py` (schema overlay coexistence, ensuring non-`cas_*` tables are untouched).
  - Total test suite: **31/31 passing**.

---

## Phase 3 — Encrypted Envelope Ingestion

**Goal:** Encrypt every uploaded record before it touches storage.

### Status: ✅ Complete (Verified with 56 passing automated tests, Ruff clean, audit trail wired)

### Completed Tasks
- [x] 3.1 `services/crypto.py` — AES-256-GCM encrypt/decrypt, HMAC-SHA-256, DEK generation
- [x] 3.2 `MinIOAdapter` — boto3/S3 API reference storage adapter with mock tests
- [x] 3.3 `services/envelope.py` — full ingestion pipeline (validate → DEK → encrypt → store → metadata persist → HMAC index)
- [x] 3.4 Upload validation (file size, extension, MIME type, image decodability)
- [x] 3.5 AAD construction (`envelope_id`, `policy_id`, `sensitivity_label`, `encryption_version`)
- [x] 3.6 `POST /envelopes` — encrypted ingestion endpoint
- [x] 3.7 `GET /envelopes` / `GET /envelopes/{id}` — policy-filtered metadata endpoints
- [x] 3.8 Audit event on every upload attempt (success and failure)
- [x] 3.9 Automated test suite for Phase 3 components (`tests/test_crypto.py`, `tests/test_envelopes.py`, updated `tests/test_storage_adapters.py`) — **56/56 passing**.

---

## Phase 4 — Authorization & Data Views

**Goal:** OPA-driven context-aware access control with minimized data views.

### Status: ✅ Complete (Verified with 68 passing automated tests, Ruff clean, fail-closed policy, rate limiting)

### Completed Tasks
- [x] 4.1 OPA integration (`policy/opa_client.py`) — HTTP client, deny-on-unavailability fail-closed
- [x] 4.2 Base Rego policies (`opa/policies/cas_se/access.rego`) — deny-by-default
- [x] 4.3 Role policies: uploader, trainer, researcher, auditor, admin rules
- [x] 4.4 `POST /search` — HMAC-token protected equality search (no plaintext index, audited)
- [x] 4.5 `POST /access-request` — context evaluation → policy decision → data view release
- [x] 4.6 Data minimization: `metadata_only`, `masked_image`, `feature_only`, `raw_image`
- [x] 4.7 Rate limiting on login and access-request endpoints via slowapi
- [x] 4.8 Automated test suite for Phase 4 components (`tests/test_policy_and_access.py`) — **68/68 passing**.

---

## Phase 5 — ML Jobs & Background Processing

**Goal:** Scoped, approved, time-limited ML job workflow with worker execution.

### Status: ✅ Complete (Verified with 78 passing automated tests, Ruff clean, CNN feature extractor & classifier workers)

### Completed Tasks
- [x] 5.1 `POST /ml-jobs` — job creation (requester, purpose, scope, view, expiry, audited)
- [x] 5.2 `GET /ml-jobs`, `GET /ml-jobs/{id}` — list and detail with scoping
- [x] 5.3 `POST /ml-jobs/{id}/approve` — admin approval, signed manifest generation with scoped envelopes
- [x] 5.4 `POST /ml-jobs/{id}/reject`, `POST /ml-jobs/{id}/cancel` — admin rejection & requester cancellation
- [x] 5.5 `GET /ml-jobs/{id}/results` — job results endpoint with classifier metrics
- [x] 5.6 Celery worker setup (`workers/celery_app.py`) with Redis broker
- [x] 5.7 Feature extraction worker (`workers/feature_extractor.py`) using CNN embeddings from approved job manifests
- [x] 5.8 Model-training worker (`workers/model_trainer.py`) on Fashion-MNIST / CIFAR-10 classifiers
- [x] 5.9 Signed job manifest — envelope IDs, allowed view, expiry, policy version, job ID, manifest token
- [x] 5.10 Per-record release auditing inside worker
- [x] 5.11 Job expiration enforcement (status automatically transitions to expired)
- [x] 5.12 Automated test suite for Phase 5 components (`tests/test_ml_jobs.py`) — **78/78 passing**.

---

## Phase 6 — Audit & Key Lifecycle

**Goal:** Tamper-evident hash chain + KEK rotation without payload re-encryption.

### Status: ✅ Complete (Verified with 85 total passing automated tests, Ruff clean, HMAC-SHA-256 chain verification, KEK rewrap, 2-of-3 Shamir SplitKey)

### Completed Tasks
- [x] 6.1 `services/audit.py` — HMAC-SHA-256 hash chaining, canonical field serialization
- [x] 6.2 All audit event types wired (login, logout, upload, search, access, job events, policy changes, key rotation, anomaly alerts)
- [x] 6.3 `GET /audit` — filterable audit query endpoint (auditor role)
- [x] 6.4 `GET /audit/verify` — chain integrity verification endpoint
- [x] 6.5 Signed checkpoint export (`GET /audit/checkpoint`)
- [x] 6.6 `services/key_management.py` — KEK versioning, DEK rewrap (rotation without payload re-encryption)
- [x] 6.7 `SplitKeyService` — simulated 2-of-3 Shamir secret sharing
- [x] 6.8 `POST /keys/rotate` — wrapping key rotation endpoint (admin only)
- [x] 6.9 `GET /policies`, `POST /policies`, `GET /policies/{id}` — policy management endpoints
- [x] 6.10 Automated test suite (`tests/test_audit_and_keys.py`) — **85/85 total tests passing**.

---

## Phase 7 — ML Evaluation & Anomaly Detection

**Goal:** Privacy vs. utility benchmarks + IsolationForest audit anomaly detection.

### Status: ✅ Complete (Verified with 93 total passing automated tests, Ruff clean, 3 baseline classifiers, IsolationForest anomaly detection, operational metrics, SVG charts)

### Completed Tasks
- [x] 7.1 Benchmark scripts — upload/encryption latency, search latency, access-decision latency, storage overhead (`scripts/run_benchmarks.py`, `app/evaluation/benchmarks.py`)
- [x] 7.2 Three baseline classifiers — Plaintext, Encrypted-RBAC, CAS-SE
- [x] 7.3 Metrics — accuracy, precision, recall, F1, training duration
- [x] 7.4 Security metrics — unauthorized access denial rate (100%), raw-data releases avoided (100%)
- [x] 7.5 Ciphertext and audit tampering detection tests (AES-GCM auth tag + HMAC-SHA-256 chain)
- [x] 7.6 `IsolationForest` anomaly detection over audit features (volume, deny spikes, raw-data requests, time-of-day, job failures, dataset diversity in `app/workers/anomaly_detector.py`)
- [x] 7.7 `GET /anomalies`, `POST /anomalies/run`, `PATCH /anomalies/{id}/review` — anomaly alerts endpoints
- [x] 7.8 `GET /metrics` — operational telemetry metrics endpoint
- [x] 7.9 Chart generation (privacy vs. utility comparisons, latency SVG charts in `evaluation_results/`)

---

## Phase 8 — Reference Dashboard & Documentation

**Goal:** Reference React/TS dashboard + full integration documentation.

### Status: ✅ Complete (Verified with 95 passing backend tests, 5 passing Playwright E2E tests, production build verified, multi-stage Docker containerization)

### Completed Tasks
- [x] 8.1 React + TypeScript frontend scaffold (`frontend/`) with Vite and TypeScript strict mode
- [x] 8.2 Pages: Login/Register (`LoginView.tsx`), Main Dashboard (`DashboardView.tsx`), Upload (`UploadView.tsx`), Search (`SearchView.tsx`), Access Request (`AccessRequestView.tsx`)
- [x] 8.3 Pages: ML Job creation/status (`MLJobsView.tsx`), Admin Approval Queue (`AdminApprovalView.tsx`), Policy Viewer (`PoliciesView.tsx`)
- [x] 8.4 Pages: Audit Viewer & Chain Verification (`AuditView.tsx`), Anomaly Alerts (`AnomaliesView.tsx`)
- [x] 8.5 Pages: Privacy-Utility Experiment Dashboard (`BenchmarksView.tsx`), System Health (`HealthView.tsx`)
- [x] 8.6 "Double-Bezel" premium dark-mode design system (`index.css`) — strictly zero keys, tokens, DEKs, or credentials exposed in UI
- [x] 8.7 Playwright E2E tests (`frontend/e2e/cas_se.spec.ts`) — login, navigation, RBAC view gates, audit chain verify runner, zero DOM secret leakage (5/5 passing)
- [x] 8.8 Integration Guide (`docs/integration_guide.md`) — step-by-step enterprise adoption, adapter implementation guide, API sequences
- [x] 8.9 Docker Compose multi-service architecture updated with `cas-se-dashboard` container (`Dockerfile`, `nginx.conf`)
- [x] 8.10 Demo data script (`scripts/seed_demo_data.py`) with all 5 roles, quick persona shortcuts, OPA policies, and demo envelopes + CLI benchmark runner (`scripts/run_benchmarks.py`)
- [x] 8.11 Client-backend integration hardening: adapter factories are resolved at the middleware boundary; federated identities maintain an adapter-authoritative CAS-SE projection; ML manifests are HMAC-authenticated server-side and verified by workers before release.

---

## Architecture Constraint Reminders

> **NEVER** store raw image payloads in the RDBMS — only ciphertext in object storage.  
> **NEVER** write secrets, keys, DEKs, or HMAC tokens to logs, API responses, or frontend state.  
> All sensitive access decisions pass through OPA — OPA unavailability = **deny**.  
> All schema changes via **Alembic only** — no startup DDL.  
> All timestamps are `TIMESTAMPTZ` UTC, **server-generated**.  
> The split-key implementation is an **academic simulation** — not production KMS/HSM.  
> Only **public/synthetic datasets** (Fashion-MNIST, CIFAR-10) in dev/demo.
