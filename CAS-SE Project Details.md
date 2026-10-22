<div align="center">

# CAS-SE: Context-Aware, Searchable, Split-Key Data Envelope
### A Privacy-Preserving Data-Governance & Access-Control Architecture for Sensitive ML Datasets

[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue.svg)](https://www.postgresql.org/)

*Developed by the B.Tech AIML Project Team (Ramdeobaba University, Nagpur)*  
**Guide:** Prof. Sonam Meshram  
**Team:** Nikhil Singh (37) • Soham Kharabe (23) • Karunya Paliwal (14) • Gaurang Daware (17) • Prajwal Khandekar (26)

</div>

---

## 🚀 Executive Summary

**CAS-SE (Context-Aware, Searchable, Split-Key Data Envelope)** is an advanced security middleware architecture designed for enterprise databases and ML pipelines handling sensitive biometric, medical, or proprietary data. 

Unlike traditional Transparent Data Encryption (TDE) that decrypts records indiscriminately upon session authentication, or static Role-Based Access Control (RBAC) that suffers from privilege creep, **CAS-SE acts as an active security gatekeeper**. It binds **per-record envelope encryption**, **protected equality search tokens**, **threshold multi-party key custody**, **context-aware policy evaluation (ABAC)**, **automatic data minimization**, and **tamper-evident hash-chained auditing** directly to every data request.

---

## 🏛️ Architecture & Integration Model

CAS-SE is deployed as an internal microservice middleware tier between enterprise application backends and existing storage infrastructure:

```
┌──────────────────────────────────────────────────────────────┐
│                  ORGANIZATION'S APPLICATION LAYER            │
│          (Web apps, ML training pipelines, microservices)    │
└─────────────────────────┬────────────────────────────────────┘
                          │  REST API calls (Private HTTPS + JWT)
                          ▼
┌──────────────────────────────────────────────────────────────┐
│                     CAS-SE MIDDLEWARE LAYER                  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────┐  │
│  │   Envelope   │ │    Policy    │ │    Audit     │ │ Key │  │
│  │   Service    │ │    Engine    │ │   Service    │ │ Svc │  │
│  │ (AES-GCM,    │ │ (Contextual  │ │ (Tamper-     │ │(2/3 │  │
│  │  Minimization│ │  ABAC / OPA) │ │  evident HMAC│ │Shamir│ │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──┬──┘  │
│         │                │                │            │     │
│  ┌──────┴────────────────┴────────────────┴────────────┴──┐  │
│  │              DATABASE ADAPTER INTERFACE                │  │
│  │      (SQLAlchemy ORM — PostgreSQL metadata store)      │  │
│  └──────┬──────────────────────────────────────────┬──────┘  │
└─────────┼──────────────────────────────────────────┼─────────┘
          │                                          │
          ▼                                          ▼
┌───────────────────┐                      ┌───────────────────┐
│  PostgreSQL 16    │                      │   Object Storage  │
│  (Metadata,       │                      │   (MinIO / S3)    │
│   HMAC Indexes,   │                      │   Encrypted       │
│   Audit Chain)    │                      │   Ciphertext Blobs│
└───────────────────┘                      └───────────────────┘
```

---

## 🛡️ Core Security Invariants

1. **Envelope Encryption ($AES-256-GCM$)**: Payloads are never stored in plaintext in object storage or raw database tables. Each record is encrypted with a unique random 32-byte Data Encryption Key (DEK). DEKs are wrapped by a versioned Master Key Encryption Key (KEK).
2. **Protected Equality Search**: Deterministic HMAC-SHA-256 tokenization allows indexed database filtering over encrypted attributes without exposing plaintext values or decrypting payloads.
3. **Context-Aware Attribute-Based Access Control (ABAC)**: Evaluates requester identity, role, declared purpose, dataset scope, active job validity, and time windows with strict **deny-by-default** semantics.
4. **Distributed Key Custody (2-of-3 Shamir Secret Sharing)**: Eliminates single-point-of-compromise vulnerabilities by requiring any 2 of 3 independent key shares (Application, Key Custodian, and Admin Recovery) to reconstruct wrapping keys.
5. **Dynamic Data Minimization**: Automatically strips unnecessary fields or transforms raw images into compact ResNet feature tensors based on requester authorization (`metadata_only`, `masked_image`, `feature_only`, `raw_image`).
6. **Tamper-Evident Audit Chain**: Append-only audit records chained via HMAC-SHA-256 enable cryptographic detection of unauthorized database modifications.

---

## 📂 Repository Structure

```text
CAS/
├── backend/
│   ├── alembic/                # Database migration overlay
│   ├── app/
│   │   ├── adapters/           # Pluggable backend adapters (Storage, Key, Identity)
│   │   ├── api/                # FastAPI REST route handlers
│   │   ├── core/               # Configuration and settings
│   │   ├── db/                 # SQLAlchemy engine & session factory
│   │   ├── models/             # SQLAlchemy ORM schema overlay models
│   │   ├── policy/             # OPA client and ABAC policy evaluators
│   │   ├── schemas/            # Pydantic data validation models
│   │   ├── services/           # Cryptography, envelope ingestion, audit trail
│   │   └── workers/            # Celery background workers
│   ├── tests/                  # Pytest unit & integration test suite
│   ├── Dockerfile              # Container build for API and Worker
│   ├── pyproject.toml          # Ruff, Mypy, and Pytest configuration
│   └── requirements.txt        # Python backend dependencies
├── docker/                     # Docker environment setup helpers
├── docs/                       # Architecture guides and integration playbook
├── evaluation_results/         # Benchmark reports & SVG performance charts
├── frontend/                   # Reference Governance Dashboard (React 19 + TypeScript)
│   ├── e2e/                    # Playwright End-to-End test suite
│   ├── src/components/         # 11 Double-bezel governance view components
│   └── Dockerfile              # Container build for reference dashboard
├── opa/
│   policies/cas_se/            # Rego access-control policies
├── scripts/
│   ├── run_benchmarks.py       # Privacy vs. utility benchmark experiment runner
│   └── seed_demo_data.py       # Rich demo database seeder (all 5 roles + personas)
├── docker-compose.yml          # Multi-service reference orchestration
├── BUILD_SEQUENCE.md           # Phased execution plan & verification logs
└── prd.md                      # Product Requirements Document
```

---

## ⚡ Quick Start (Development & Testing)

### 1. Environment Configuration
Copy the sample environment template and generate secure cryptographic keys:
```bash
cp .env.example .env
```
Generate test keys:
```bash
# Generate 32-byte base64 KEK
python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"

# Generate 64-char hex keys for JWT, HMAC Index, and Audit Chain
python -c "import secrets; print(secrets.token_hex(32))"
```

### 2. Run with Docker Compose
Boot the complete stack (API, Dashboard UI, OPA, Celery Worker, PostgreSQL, MinIO, Redis):
```bash
docker compose up --build
```

### 3. Seed Demo Data & Run Benchmarks
```bash
python scripts/seed_demo_data.py
python scripts/run_benchmarks.py
```

### 4. Verify Health & Telemetry
```bash
curl http://localhost:8000/health
# {"status":"ok","service":"CAS-SE","version":"0.1.0"}

curl http://localhost:8000/metrics
# {"status":"healthy","envelopes_total":3,"audit_events_total":4,...}
```

---

## 🧪 Testing & Quality Assurance

Run the comprehensive pytest backend test suite (93 tests covering cryptography, OPA, ML feature extraction, and audit chain verification):
```bash
pytest backend/tests/ -v
```

Run linter and format checks:
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

## 📊 Empirical Evaluation Results

| Experiment Metric | Plaintext Baseline | Encrypted Storage + RBAC | CAS-SE Architecture |
| :--- | :---: | :---: | :---: |
| **Ingestion Latency (1k records)** | $12.4\text{ ms}$ | $38.2\text{ ms}$ | $44.1\text{ ms}$ ($<15\%$ overhead) |
| **Search Query Latency** | $2.1\text{ ms}$ | Failed (Unsearchable) | $4.8\text{ ms}$ (HMAC token index) |
| **Least-Privilege Enforcement** | $0\%$ (Exposes Raw Data) | $20\%$ (Static Roles) | $100\%$ (Context & Minimization) |
| **Tamper Detection** | None | None | Instant (Cryptographic Hash Chain) |
| **ML Model Accuracy (ResNet)** | $94.2\%$ | $94.2\%$ | $93.8\%$ ($>90\%$ utility retained) |

---

## 📜 Academic License & Disclaimer

Distributed under the **MIT License**. See `LICENSE` for more information.

*Note: This architecture is a proof-of-concept middleware designed for secure enterprise MLOps. It does not replace hardware-backed KMS/HSM in high-security production environments or prevent user-side screen capture after lawful data release.*
