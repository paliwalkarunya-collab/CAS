<div align="center">
  
# CAS-SE: Context-Aware, Searchable, Split-Key Data Envelope
A Privacy-Preserving Data-Governance & Access-Control Architecture for Sensitive ML Datasets

![CAS-SE Banner](./cas-se-banner.png)
[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue.svg)](https://www.postgresql.org/)

*Developed by the B.Tech AIML Project Team (Ramdeobaba University, Nagpur)*  
**Guide:** Prof. Sonam Meshram  
**Team:** Nikhil Singh (37) • Soham Kharabe (23) • Karunya Paliwal (14) • Gaurang Daware (17) • Prajwal Khandekar (26)

</div>

> **CAS-SE** is a privacy-preserving data-governance architecture designed to be integrated into an organization's existing database and storage infrastructure.
>
> **It is not a standalone application or a database replacement.** It is a middleware layer comprising schema overlays, policy engines, and cryptographic primitives that intercept data ingestion, search, and access operations to enforce **least-privilege envelope encryption**, **context-aware authorization**, **protected search**, **data minimization**, and **tamper-evident auditing** for sensitive ML datasets.

The `frontend/` folder is an optional reference dashboard for demonstrations
only. Client deployments integrate the `backend/` middleware into their own
application and identity stack; CAS-SE is not delivered as a web application.

---

## 🏛️ Architecture & Integration Model

An adopting organization deploys CAS-SE as a middleware tier between their application/pipeline services and their existing database/storage tiers:

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

## 🛡️Core Principles

1. **Envelope Encryption**: Payloads are never stored in plaintext in object storage and never stored as raw blobs in the database. Each record is encrypted with a fresh random 32-byte Data Encryption Key (DEK) via AES-256-GCM. The DEK is wrapped by a Key Encryption Key (KEK).
2. **Pluggable Adapter Interfaces**: Standard Python Protocols allow organizations to plug in their existing infrastructure:
   - `StorageAdapter`: MinIO, AWS S3, Azure Blob, GCS, or Local Filesystem.
   - `KeyServiceAdapter`: AWS KMS, HashiCorp Vault, HSM, EnvVar (demo), or Split-Key (2-of-3 Shamir secret sharing simulation).
   - `IdentityAdapter`: BuiltIn (JWT + Argon2), LDAP, OIDC, or SAML.
3. **Protected Equality Search**: HMAC-SHA-256 tokenization prevents indexing or querying sensitive terms in plaintext.
4. **Context-Aware Policy Engine (OPA)**: Open Policy Agent with Rego policies evaluates requester identity, role, purpose, dataset scope, and job approval status with fail-closed (deny-by-default) semantics.
5. **Data Minimization**: Decrypted payloads are tailored to the requester's authorized view (`metadata_only`, `masked_image`, `feature_only`, `raw_image`).
6. **Tamper-Evident Hash-Chained Audit Trail**: Append-only audit records chained via HMAC-SHA-256 enable cryptographic detection of tampering or deletion.

---

## ⚙️Pluggable Adapters

### Storage Adapter (`app.adapters.storage.StorageAdapter`)
```python
class StorageAdapter(Protocol):
    def put_object(self, key: str, data: bytes) -> str: ...
    def get_object(self, key: str) -> bytes: ...
    def delete_object(self, key: str) -> None: ...
    def health_check(self) -> bool: ...
```
- `MinIOAdapter`: S3-compatible backend using `boto3`.
- `LocalFileAdapter`: Filesystem backend for local testing and isolated development.

### Key Service Adapter (`app.adapters.key_service.KeyServiceAdapter`)
```python
class KeyServiceAdapter(Protocol):
    def get_current_kek(self) -> tuple[bytes, int]: ...
    def get_kek_by_version(self, version: int) -> bytes: ...
    def rotate_kek(self) -> tuple[bytes, int]: ...
    def is_unlocked(self) -> bool: ...
    def get_status(self) -> dict[str, Any]: ...
    def current_kek_version(self) -> int: ...
    def wrap_dek(self, dek: bytes) -> tuple[str, int]: ...
    def unwrap_dek(self, wrapped_dek: str, version: int) -> bytes: ...
```
- `EnvVarKeyService`: Environment-variable driven KEK versioning (`KEY_SERVICE_ADAPTER=env`).
- `SplitKeyService`: 2-of-3 Shamir Secret Sharing key management (`KEY_SERVICE_ADAPTER=split`).

### Identity Adapter (`app.adapters.identity.IdentityAdapter`)
```python
class IdentityAdapter(Protocol):
    def resolve_user(self, token: str) -> CASUser: ...
    def get_user_role(self, user_id: UUID) -> str: ...
```
- `BuiltInIdentity`: Reference Argon2 password hashing and short-lived JWT access tokens with refresh token rotation.

---

## 📂Directory Structure

```text
CAS/
├── backend/
│   ├── alembic/              # Database migration overlay
│   ├── app/
│   │   ├── adapters/         # Pluggable backend adapters (Storage, Key, Identity)
│   │   ├── api/              # REST API route handlers
│   │   ├── core/             # Configuration, settings
│   │   ├── db/               # SQLAlchemy engine & session factory
│   │   ├── models/           # SQLAlchemy ORM schema overlay models
│   │   ├── policy/           # OPA client and policy evaluators
│   │   ├── schemas/          # Pydantic validation schemas
│   │   ├── services/         # Cryptography, envelope ingestion, audit trail
│   │   └── workers/          # Celery background workers
│   ├── tests/                # Unit and integration test suite
│   ├── Dockerfile            # Container build for API and Worker
│   ├── pyproject.toml        # Ruff, Mypy, and Pytest configuration
│   └── requirements.txt      # Python dependencies
├── docker/                   # Docker environment helpers
├── docs/                     # Architecture and integration guides
├── evaluation_results/       # Empirical benchmark reports & SVG charts
├── frontend/                 # Reference Governance & Access Dashboard (React 19 + TypeScript)
│   ├── e2e/                  # Playwright End-to-End test suite
│   ├── src/components/       # 11 Double-bezel governance views
│   └── Dockerfile            # Container build for reference dashboard
├── opa/
│   └── policies/cas_se/      # Rego access-control policies
├── scripts/
│   ├── run_benchmarks.py     # Privacy vs. utility benchmark experiment runner
│   └── seed_demo_data.py     # Rich demo database seeder (all 5 roles + personas)
├── docker-compose.yml        # Multi-service reference orchestration
├── BUILD_SEQUENCE.md         # Phased execution plan & verification logs
└── prd.md                    # Product Requirements Document
```

---

## ⚡Quick Start (Development)

### 1. Environment Configuration
Copy the sample environment file:
```bash
cp .env.example .env
```
Ensure you generate secure keys for your local test environment:
```bash
# Generate 32-byte base64 KEK
python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"

# Generate 64-char hex keys for JWT, HMAC Index, and Audit Chain
python -c "import secrets; print(secrets.token_hex(32))"
```

### 2. Seed Demo Data & Run Benchmarks
Populate the database with demo accounts for all 5 roles, policies, and envelopes:
```bash
python scripts/seed_demo_data.py
```

Run empirical privacy vs utility benchmark experiments (generates SVG charts in `evaluation_results/`):
```bash
python scripts/run_benchmarks.py
```

### 3. Run Native Local Development (No Docker Required)
You can launch the entire stack (OPA engine, FastAPI backend, and React dashboard) with a single command:
```powershell
# Double-click or run from terminal:
.\start-dev.bat
# or in PowerShell:
.\start-dev.ps1
```
To cleanly stop all development services:
```powershell
.\stop-dev.bat
# or
.\stop-dev.ps1
```

### 4. Run with Docker Compose
```bash
docker compose up --build
```
This boots:
- `cas-se-api` on port `8000`
- `cas-se-dashboard` (optional reference demonstration UI) on port `3000`
- `cas-se-opa` on port `8181`
- `cas-se-worker` (Celery background worker)
- `cas-postgres` on port `5432`
- `cas-minio` on ports `9000` (API) & `9001` (Console)
- `cas-redis` on port `6379`

### 4. Verify Health & Telemetry
```bash
curl http://localhost:8000/health
# {"status":"ok","service":"CAS-SE","version":"0.1.0"}

curl http://localhost:8000/metrics
# {"status":"healthy","envelopes_total":3,"audit_events_total":4,...}
```

---

## Shamir Secret Sharing Key Management (2-of-3 SSS)

CAS-SE provides a fully integrated 2-of-3 Shamir Secret Sharing (SSS) key management workflow implemented in `app.adapters.key_service.SplitKeyService`.

### Cryptographic Hierarchy in CAS-SE

| Key Type | Scope | Algorithm | Responsibility / Storage |
| :--- | :--- | :--- | :--- |
| **DEK (Data Encryption Key)** | Per-Envelope | AES-256-GCM (random 32 bytes) | Encrypts raw data payloads; stored only as `wrapped_dek` in RDBMS envelope metadata. |
| **KEK (Key Encryption Key)** | Global Versioned | AES-256 Key Wrap (RFC 3394 / GCM) | Wraps and unwraps DEKs. In `SplitKeyService`, reconstructed in RAM from custodian shares. |
| **HMAC Index Key** | Global Static | HMAC-SHA256 (`CAS_HMAC_INDEX_KEY`) | Computes blind deterministic search tokens over metadata without revealing plaintext. |
| **Audit Integrity Key** | Global Static | HMAC-SHA256 (`CAS_AUDIT_HMAC_KEY`) | Links audit records into a tamper-evident cryptographic hash chain. |

### How 2-of-3 Secret Sharing Works

Shamir Secret Sharing represents a 256-bit secret $S$ as the constant term of a random degree-1 polynomial over the prime field $\mathbb{F}_p$, where $p = 2^{256} + 297$ (the smallest prime greater than $2^{256}$):
$$f(x) = (S + a_1 x) \pmod p$$

Three custodian shares are generated by evaluating the polynomial at distinct non-zero coordinates:
- Share 1: $(1, f(1) \pmod p)$
- Share 2: $(2, f(2) \pmod p)$
- Share 3: $(3, f(3) \pmod p)$

Any 2 shares $(x_1, y_1)$ and $(x_2, y_2)$ reconstruct the original secret $S$ via Lagrange interpolation at $x = 0$:
$$S = \left( y_1 \frac{x_2}{x_2 - x_1} + y_2 \frac{x_1}{x_1 - x_2} \right) \pmod p$$

- **Threshold Guarantee**: Any pair of valid shares ($1+2$, $1+3$, or $2+3$) uniquely recovers the exact 256-bit KEK.
- **Information-Theoretic Security**: A single share provides zero information about $S$, because for any candidate secret $S'$, there exists a unique polynomial slope $a_1'$ consistent with $(x_1, y_1)$.
- **Strict Validation**: Share strings follow `x-hex_y`. Inputs are validated for $1 \le x < p$, $0 \le y < p$, duplicate $x$ detection, non-hex rejection, and exact 32-byte bounds ($0 \le S < 2^{256}$).

### Configuration & Local Setup

To activate Shamir-based key management, configure `.env`:

```env
# Enable Shamir split-key adapter
KEY_SERVICE_ADAPTER=split
SPLIT_KEY_THRESHOLD=2

# Option A: Start locked (recommended custodian workflow)
SPLIT_KEY_SHARES=[]

# Option B: Pre-provision test shares for automated headless testing
# SPLIT_KEY_SHARES=["1-...", "2-..."]
```

When deployed via Docker Compose, `docker-compose.yml` automatically forwards `KEY_SERVICE_ADAPTER`, `SPLIT_KEY_SHARES`, and `SPLIT_KEY_THRESHOLD` to both `cas-se-api` and `cas-se-worker`.

### Share Lifecycle & Custodian Workflow

1. **Bootstrap / Initialization (`POST /keys/shamir/init`)**:
   - Generates a fresh cryptographically random 256-bit KEK using `os.urandom(32)`.
   - Evaluates a fresh random polynomial and splits the KEK into 3 custodian shares.
   - Shares are returned **once** in the API response.
   - Custodians distribute shares across independent custody domains (e.g., separate offline storage or hardware tokens).
2. **Fail-Closed State**:
   - When the service starts without configured shares, it enters a `locked` state (`is_unlocked() == False`).
   - Any attempt to ingest data (`POST /envelopes`) or access records (`POST /access/evaluate`) fails immediately with `HTTP 503 Service Unavailable` (`Key service is locked. Custodian threshold shares required to unlock.`).
3. **Threshold Recovery / Unlock (`POST /keys/shamir/unlock`)**:
   - Authorized administrators submit any 2 valid custodian shares via API or the Admin Approval Dashboard.
   - The KEK is reconstructed strictly in memory. Submitted shares and raw KEK material are never written to disk, database, or application logs.
4. **Key Rotation (`POST /keys/rotate`)**:
   - Authorized administrators trigger KEK rotation.
   - A fresh KEK version ($N+1$) is generated and split into a new 3-share set.
   - All stored envelope DEKs are unwrapped with KEK $N$ and rewrapped under KEK $N+1$ without modifying underlying ciphertext blobs.
   - Historical KEK versions are retained in memory so existing records remain decryptable.
5. **Memory Clearing / Lockout (`POST /keys/shamir/lock`)**:
   - Calling the lock endpoint purges the active KEK from memory and transitions the service back to fail-closed state.

### Academic Simulation vs. Production Deployment

> [!WARNING]
> The current `SplitKeyService` implementation is an **academic demonstration and development simulation**.

- **Memory Residency**: In this reference implementation, the reconstructed KEK resides in the process memory of the Python application. While temporary buffers are cleared where practical, Python's garbage collection and immutable `bytes` objects do not guarantee immediate zeroization.
- **Co-located Storage**: Storing all three shares in a single `.env` file, database table, or container volume completely defeats threshold security.
- **Production Requirements**:
  1. **Independent Custodians**: Shares must be held by separate legal or operational entities and transmitted over authenticated mTLS channels.
  2. **Hardware Security Modules (HSMs)**: Production deployments should replace in-process KEK reconstruction with HSM quorum authorization (e.g., PKCS#11 multi-operator authentication or AWS KMS / HashiCorp Vault multi-custodian unseal).
  3. **Process Isolation**: Sensitive key material must use OS-level memory locking (`mlock`) and sodium/C-level secure memory allocators.

---

## 🧪Testing & Quality Assurance

Run backend pytest suite (115 tests covering crypto, OPA, ML jobs, audit chain, anomalies, benchmarks, and Shamir key management):
```bash
pytest backend/tests/ -v
```

Lint and format checks:
```bash
ruff check backend/ scripts/
ruff format --check backend/ scripts/
```

Run frontend Playwright E2E tests:
```bash
cd frontend
npm run test:e2e
```

---



## 🎥 **Watch the video demonstration:** 
[Meet CAS-SE.mp4](./Meet%20CAS-SE.mp4)

## 📜 Known Academic Limitations & Ethics

- **Equality-pattern leakage**: HMAC tokens disclose whether indexed terms are identical.
- **Academic Simulation**: Split-key Shamir recovery is a software prototype, not a hardware-backed HSM/KMS.
- **Synthetic Datasets**: Only synthetic or approved non-sensitive public datasets (Fashion-MNIST, CIFAR-10) are used for testing.
