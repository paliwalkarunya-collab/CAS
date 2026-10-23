# CAS-SE — Final End-to-End Application Verification Report

**Execution Timestamp:** 2026-10-22T19:57:30Z  
**Host Environment:** Windows Native (Python 3.13.1, Node.js v20.x, PowerShell)  
**Configuration:** `KEY_SERVICE_ADAPTER=split`, `STORAGE_ADAPTER=local`, `IDENTITY_ADAPTER=builtin`  
**Scope:** Native Development Stack (Docker and Docker Compose strictly excluded)  
**Final Status:** **PASS**

---

## 1. Executive Summary

This document certifies the comprehensive, live end-to-end verification of the **CAS-SE (Confidential Access System - Secure Edition)** middleware and reference dashboard. The application was inspected, executed, debugged, and verified under native Windows execution without containerization. 

All 12 prescribed verification procedures were executed sequentially against live instances of the FastAPI backend (`:8000`), the OPA policy engine (`:8181`), and the Vite React frontend (`:5173`). Cryptographic invariants, fail-closed enforcement, Shamir secret sharing (2-of-3 threshold), key rotation with zero plaintext rewrap, and process restart recovery were validated with zero regressions.

---

## 2. 12-Step Verification Audit Trail

### Step 1: Start Backend and Frontend Using Native Workflow
- **Services Verified:**
  - OPA Policy Engine: `http://127.0.0.1:8181/v1/data` (HTTP 200)
  - FastAPI Backend: `http://127.0.0.1:8000/health` (HTTP 200, version `0.1.0`)
  - Vite Frontend: `http://127.0.0.1:5173/` (HTTP 200)
- **Commands Executed:**
  ```powershell
  # OPA Policy Engine
  .\opa\opa.exe run --server --addr :8181 opa\policies\
  # Vite Governance Dashboard
  npm run dev -- --host 127.0.0.1 --port 5173
  # FastAPI Application Server
  python -m uvicorn app.main:app --app-dir backend --port 8000
  ```
- **Evidence:** HTTP 200 returned on all health and index routes across all three native processes.

---

### Step 2: Verify `KEY_SERVICE_ADAPTER=split` at Runtime
- **Command:** `GET http://127.0.0.1:8000/keys/status` (Authenticated as Administrator)
- **Result Payload:**
  ```json
  {
    "adapter": "split",
    "is_unlocked": false,
    "threshold": 2,
    "total_shares": 3,
    "current_version": 2,
    "shares_provided_count": 0,
    "recovered_versions": [],
    "message": "Key service is LOCKED. Requires 2-of-3 Shamir shares to unlock."
  }
  ```
- **Finding:** The runtime key-service instance is an exact instance of `SplitKeyService`. No fallback to `EnvVarKeyService` occurred.

---

### Step 3: Administrator Authentication & Key-Status Consistency
- **Command:** `POST http://127.0.0.1:8000/auth/login`
  - Body: `{"username": "admin", "password": "Pass123!"}`
- **Response:** HTTP 200, JWT token returned with `bearer` token type.
- **Frontend Verification:** Admin UI displays the Key Management view, double-bezel cards, and current locked/unlocked indicator corresponding directly to backend status.

---

### Step 4: Fresh 2-of-3 Shamir Secret Sharing Initialization & Threshold Verification
- **Command:** `POST http://127.0.0.1:8000/keys/shamir/init`
- **Response:** HTTP 200, version `1`, threshold `2`, total shares `3`. Three hex-encoded shares provisioned.
- **Negative & Positive Threshold Tests:**
  1. **Single Share Unlock Attempt:**
     - Input: `[v1_shares[0]]`
     - Response: **HTTP 400 Bad Request** (`"SplitKeyService requires at least 2 shares to reconstruct the KEK; got 1"`)
  2. **Duplicate Share Unlock Attempt:**
     - Input: `[v1_shares[0], v1_shares[0]]`
     - Response: **HTTP 400 Bad Request** (`"Duplicate share x-coordinate 1 detected; shares must be distinct"`)
  3. **Tampered Share Unlock Attempt:**
     - Input: `[v1_shares[0], tampered_share]`
     - Response: **HTTP 400 Bad Request** (`"Reconstructed KEK failed Key Check Value (KCV) verification for version 1; shares are corrupted, forged, or belong to a different key"`)
  4. **All Combinations of Valid Shares:**
     - `(Share 1, Share 2)`: **HTTP 200 OK**, service unlocked (`is_unlocked: true`)
     - `(Share 1, Share 3)`: **HTTP 200 OK**, service unlocked (`is_unlocked: true`)
     - `(Share 2, Share 3)`: **HTTP 200 OK**, service unlocked (`is_unlocked: true`)

---

### Step 5: Upload Disposable Test File & Verify Real Envelope Encryption
- **Upload Payload:** Valid 8x8 red PNG (`patient_sample_v1.png`), 75 bytes, sensitivity `restricted`, dataset `disposable_verification_ds`.
- **Command:** `POST http://127.0.0.1:8000/envelopes`
- **Response:** **HTTP 201 Created**, `envelope_id = 7d37f64d-fcb6-4ec6-a3f1-6b9240223458`.
- **Database Inspection (`cas_data_envelopes`):**
  - `kek_version`: `1`
  - `wrapped_dek`: 80-character base64 string (`TF6WzbHdASfJvmr+qDs2...`)
  - `ciphertext_hash`: `fd4d5d94f02cac85...`
  - `object_uri`: `envelopes/05815928e04b4ca5832ac46ecc446441/acfde448e25d4c62a4e7979750082442`
  - **Zero plaintext persisted** in SQLite.
- **Storage Verification:** Verified local object storage file contains AES-256-GCM ciphertext, not plaintext image bytes.

---

### Step 6: Lock Key Service and Confirm Fail-Closed Behavior
- **Command:** `POST http://127.0.0.1:8000/keys/shamir/lock`
- **Status Response:** `is_unlocked = false`.
- **Fail-Closed Verification:**
  - **Upload Attempt While Locked:** `POST /envelopes` returned **HTTP 503 Service Unavailable** (`"Key service is locked -- Shamir secret reconstruction required before data ingestion."`)
  - **Decryption Attempt While Locked:** `POST /access-request` returned **HTTP 503 Service Unavailable** (`"Key service is locked -- Shamir secret reconstruction required before data can be decrypted."`)

---

### Step 7: Unlock Using 2 Shares & Verify Authorized Decryption
- **Command:** `POST http://127.0.0.1:8000/keys/shamir/unlock` with shares `(1, 3)`
- **Response:** **HTTP 200 OK**, `is_unlocked = true`.
- **Access Request:** `POST http://127.0.0.1:8000/access-request` for envelope `7d37f64d-fcb6-4ec6-a3f1-6b9240223458` with view `raw_image` and purpose `model_training`.
- **Response:** **HTTP 200 OK**, `decision: raw_image`, `data_b64` returned.
- **Payload Verification:** Base64-decoded bytes match original red PNG bytes **exactly** (75 bytes, SHA-256 match).

---

### Step 8: Rotate KEK & Verify Dual-Version Decryption
- **Command:** `POST http://127.0.0.1:8000/keys/rotate`
- **Response:** **HTTP 200 OK**, rotated from KEK v1 to v2. 3 new shares provisioned for v2. Envelopes rewrapped without touching ciphertext.
- **New Ingestion under v2:** Uploaded 8x8 green PNG (`patient_sample_v2.png`, 76 bytes). `POST /envelopes` returned **HTTP 201 Created** (`envelope_id = 20f1318c-13ac-486a-8006-5f324eca7fb6`).
- **Decryption of Both Envelopes:**
  - **Envelope 1 (Rewrapped to v2):** `POST /access-request` returned **HTTP 200 OK**, exact byte match with red PNG.
  - **Envelope 2 (Created under v2):** `POST /access-request` returned **HTTP 200 OK**, exact byte match with green PNG.

---

### Step 9: Backend Process Restart & Custodian Recovery Workflow
- **Procedure:**
  1. The running Uvicorn backend process was terminated (`manage_task kill`).
  2. A fresh backend process was launched on port 8000.
  3. **Cold Boot State Verified:**
     - `GET /keys/status` returned `is_unlocked = false`, `shares_provided_count = 0`.
     - Zero plaintext KEK or shares persisted on disk or in the database.
  4. **Fail-Closed Verification:**
     - `POST /access-request` for envelope 2 returned **HTTP 503 Service Unavailable**.
  5. **Active KEK Custodian Recovery:**
     - Submitted shares 1 and 2 for KEK v2 to `POST /keys/shamir/unlock`.
     - Response: **HTTP 200 OK**, `"KEK v2 successfully reconstructed in memory from threshold shares"`.
     - `GET /keys/status`: `is_unlocked = true`, `recovered_versions = [2]`.
  6. **Decryption of Envelope 2 (v2):** Exact byte match with original green PNG (76 bytes).
  7. **Decryption of Envelope 1 (rewrapped to v2):** Exact byte match with original red PNG (75 bytes).
  8. **Historical KEK Custodian Recovery (v1):**
     - Submitted shares 2 and 3 for KEK v1 with `version = 1` to `POST /keys/shamir/unlock`.
     - Response: **HTTP 200 OK**, `"KEK v1 successfully reconstructed in memory from threshold shares"`.
     - `GET /keys/status`: `recovered_versions = [1, 2]`.

---

### Step 10: Frontend and Backend Consistency in Real Browser
- **Tool:** Playwright Browser Automation (`@playwright/test` running Chromium)
- **Suite:** `frontend/e2e/cas_se.spec.ts`
- **Results:**
  - `User authentication and quick demo persona switching`: **PASSED** (3.9s)
  - `Navigation tabs render double-bezel views properly`: **PASSED** (1.2s)
  - `Active role simulation switching enforces RBAC view gates`: **PASSED** (1.3s)
  - `Audit chain verification runner in Auditor view`: **PASSED** (1.4s)
  - `Dedicated Audit-Chain Verification Page`: **PASSED** (945ms)
  - `Zero secrets, DEKs, or credentials leaked in DOM`: **PASSED** (840ms)
- **Total:** **6 passed in 10.6s**, 0 browser console errors, 0 failed network requests.

---

### Step 11: Confirmation of Disposable Test Environment
- **Database Backup:** `cas_dev.db.bak` verified intact (237,568 bytes).
- **Test Partitioning:** All test envelopes created in steps 1-9 were tagged with `dataset_id="disposable_verification_ds"` and used generated in-memory PNGs. No existing user data was altered or deleted.

---

### Step 12: Regression Test Suites
- **Backend Test Suite:** `pytest backend/tests -v`
  - **119 passed**, 0 failed, 7 deprecation warnings in 23.63s.
- **Frontend Production Build:** `npm run build`
  - 0 TypeScript errors, production bundle compiled cleanly in 1.12s.
- **Frontend Code Linter:** `npm run lint` (oxlint)
  - 0 errors across 21 files.
- **Python Linter:** `ruff check backend`
  - All checks passed.
- **Python Type Checker:** `mypy backend/app --ignore-missing-imports`
  - Success: no issues found in 49 source files.

---

## 3. Architecture Limitations & Production Custody Notice

> [!WARNING]
> **Independent Share Custody & Multi-Process Scaling Boundary:**
> 1. In this reference implementation, `SplitKeyService` stores reconstructed keys in application process memory. In a multi-worker deployment (e.g. `gunicorn -w 4`), each worker maintains its own isolated memory space unless an enterprise Key Management Service (KMS) or Hardware Security Module (HSM) adapter (e.g., AWS KMS, HashiCorp Vault Transit, PKCS#11) is configured.
> 2. Independent share custody requires administrative custodians to hold their individual share strings on physically separated, secure devices (e.g. smartcards, hardware tokens, or air-gapped password managers). Storing all shares in the same configuration file, database, or secret manager violates the 2-of-3 security boundary.
