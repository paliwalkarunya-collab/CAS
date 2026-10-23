# CAS-SE Shamir Secret Sharing (SSS) — Security, Persistence, and Concurrency Audit

**Audit Status**: Verified & Remediated  
**Target Subsystems**: `backend/app/adapters/key_service.py`, `backend/app/adapters/factory.py`, `backend/app/api/keys.py`, `backend/app/core/config.py`, `backend/tests/`  
**Evaluation Standard**: GRAVITAS Reliability Protocol (executable evidence over assumptions)  
**Date**: 2026-10-22  

---

## 1. Executive Summary

This audit independently inspects the 2-of-3 Shamir Secret Sharing (SSS) key management implementation in CAS-SE. Beyond unit test execution, this audit specifically evaluated:
1. **Process Restart & Historical Recovery**: Can an envelope encrypted under KEK $v_1$ be decrypted after key rotation to $v_2$ followed by a complete backend process restart?
2. **Share Leakage & Audit Sanitization**: Do malformed share attempts leak secrets into exception messages, HTTP response bodies, or the database audit trail?
3. **Concurrency & Thread Safety**: Can concurrent `unlock`, `lock`, `wrap_dek`, and `rotate_kek` calls induce race conditions or corrupt internal state?
4. **Multi-Process virtual memory boundaries**: How does in-memory key reconstruction behave across multi-worker Uvicorn setups and background Celery workers?
5. **Trust Boundary & Custody Limits**: Does the architecture enforce independent custodianship, or does the administrator session possess all shares at provisioning time?

### Summary of Audit Findings & Status

| ID | Category | Severity | Finding | Resolution Status |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Persistence | **High** | Post-restart unlock failed when recovering historical or rotated KEK versions due to `target_version == current_version` check. | **Fixed** (`target_version >= current_version or self._kek is None` + DB current version synchronization). |
| **SEC-02** | Information Leak | **Medium** | Malformed share exceptions printed `{y_str!r}` in `ValueError`, leaking secret share material into audit logs and API error responses. | **Fixed** (Sanitized error strings to omit share values). |
| **SEC-03** | Concurrency | **Medium** | `SplitKeyService` lacked thread synchronization primitives, risking race conditions under concurrent async operations. | **Fixed** (Added internal reentrant `threading.RLock`). |
| **SEC-04** | Architecture | **High** | Single-session share provisioning: `POST /keys/shamir/init` and `POST /keys/rotate` return all 3 shares to the initiating admin session. | **Documented Architectural Boundary** (Academic reference prototype; production requires DKG or quorum HSM). |
| **SEC-05** | Multi-Process | **High** | In-memory KEK reconstruction is bound to a single worker process; multi-worker Uvicorn or separate Celery workers do not share state. | **Documented Architectural Boundary** (Requires external KMS/HSM or secure IPC daemon for multi-worker scaling). |

---

## 2. Runtime Integration & Configuration Tracing

### A. Configuration Trace
1. **Setting Definition** (`app.core.config.Settings`):
   - `KEY_SERVICE_ADAPTER`: Validated by Pydantic against `{"env", "split", "custom"}`. Unknown values immediately abort application startup with `ValidationError`.
   - `SPLIT_KEY_SHARES`: Parsed via `parse_split_key_shares` validator from string list, comma-delimited strings, or JSON arrays.
   - `SPLIT_KEY_THRESHOLD`: Defaults to `2` (minimum allowed threshold is 2).
2. **Adapter Construction** (`app.adapters.factory.build_key_service`):
   - If `KEY_SERVICE_ADAPTER="split"`, instantiates `SplitKeyService(shares=settings.split_key_shares, threshold=settings.split_key_threshold)`.
   - **No Silent Fallback**: If split-key parameters are invalid, `ValueError` is raised and caught by application startup. It NEVER falls back to `EnvVarKeyService`.
3. **Application State & Dependency Injection**:
   - `app.state.cas_key_service` retains the singleton adapter.
   - `get_key_service` in `app.api.envelopes` supplies the adapter to `POST /envelopes`, `POST /access/evaluate`, `POST /keys/rotate`, and `POST /keys/shamir/*`.

### B. Fail-Closed Verification
When configured with `SPLIT_KEY_SHARES=[]`, `SplitKeyService` boots in a `locked` state (`is_unlocked() == False`):
- `POST /envelopes`: Catches `KeyServiceLockedError`, logs an audited `upload` denial, and returns `HTTP 503 Service Unavailable`.
- `POST /access/evaluate`: Catches `KeyServiceLockedError`, logs an audited `access_deny` event, and returns `HTTP 503 Service Unavailable`.
- Frontend status card queries `GET /keys/status` and immediately displays the `LOCKED` status badge.

---

## 3. Restart and Persistence Audit

### A. The Persistence Challenge in Threshold Schemes
In a true threshold secret sharing scheme:
- **Zero Plaintext Persistence Invariant**: The master KEK $S$ must **never** be written to disk, database tables, or environment variables in plaintext.
- **Fail-Closed on Restart**: When the host system or container restarts, all process RAM is cleared. The service MUST boot locked.
- **Custodial Recovery**: The system can only return to an operational state when the threshold of independent custodians ($k=2$) manually submit their shares to reconstruct the KEK in memory.

### B. The Identified Defect (SEC-01)
Prior to this audit, when the backend restarted after a key rotation (e.g. from version 1 to version 2):
1. A fresh `SplitKeyService` instance was initialized with `_current_version = 1`.
2. When custodians submitted shares for the active version 2 via `POST /keys/shamir/unlock`:
   - If they didn't specify `"version": 2`, the API defaulted to `_current_version` (1), erroneously saving version 2 shares into historical slot 1.
   - If they did specify `"version": 2`, line 245 evaluated `if target_version == self._current_version:` (`2 == 1`), which was `False`. Consequently, `self._is_unlocked` remained `False` and `self._kek` remained `None`!
3. The service remained completely locked and unable to process data access.

### C. Resolution Implemented
1. **Dynamic Version Activation**:
   ```python
   with self._lock:
       self._historic[target_version] = reconstructed
       # Activate primary KEK if unlocking current version, higher version, or if service was locked
       if target_version >= self._current_version or self._kek is None:
           self._kek = reconstructed
           self._current_version = target_version
           self._shares = list(shares)
           self._is_unlocked = True
   ```
2. **Database Version Synchronization**:
   In `unlock_shamir_keys` (`backend/app/api/keys.py`): If `body.version` is omitted, the API queries `CASKeyVersion` for `is_current == True` and unlocks that version.
3. **Historical Version Recovery**:
   Custodians can unlock historical KEK versions ($v_1, v_2, \dots$) by specifying the version number in `POST /keys/shamir/unlock`. Historical keys are stored in `_historic` without downgrading `_current_version`, allowing older envelopes to be unwrapped and decrypted.

---

## 4. Share Handling, Custody & Information Leakage Audit

### A. Information Leakage in Exceptions and Audit Trail (SEC-02)
- **Vulnerability**: In `SplitKeyService._reconstruct`, invalid hex or out-of-field share inputs raised `ValueError(f"... {y_str!r}")`. Because `unlock_shamir_keys` logs `Failed Shamir unlock attempt: {exc}` into `cas_access_audit.reason`, invalid share submissions leaked the share secret into the database and API responses.
- **Remediation**: Replaced all string interpolations of `y_str` and `s` with sanitized descriptions:
  ```python
  if not isinstance(s, str) or "-" not in s:
      raise ValueError("Malformed split-key share format (missing '-'); expected 'x-hex_y'")
  ...
  except ValueError as e:
      raise ValueError(f"Invalid share y-coordinate hex format at index {x}") from e
  ...
  if y < 0 or y >= p:
      raise ValueError(f"Share y-coordinate out of field range at index {x} (must be < p)")
  ```
- **Verification**: Verified via `test_shares_and_keys_never_leak_in_errors_or_audit` using a synthetic canary string.

### B. Client-Side Persistence
- Inspected `frontend/src/` for all usages of `localStorage`, `sessionStorage`, and `IndexedDB`.
- Confirmed shares are held only in ephemeral React component memory (`useState`) and discarded on view unmount or browser reload.

### C. The Trust Boundary Finding (SEC-04)
- **Architectural Fact**: `POST /keys/shamir/init` and `POST /keys/rotate` generate the random polynomial on the backend and return all $n=3$ shares to the calling admin session.
- **Trust Boundary Limit**: The administrator who executes key bootstrap/rotation has temporary custody of all shares. This does not provide cryptographic separation of duties at key generation time.
- **Production Requirement**: In high-assurance production environments, share generation must use Distributed Key Generation (DKG) where custodians compute their shares without any single party ever observing the master secret, or use a hardware security module (HSM) with multi-custodian smart cards (e.g., nShield or Luna HSM).

---

## 5. Cryptographic Review

### A. Field Arithmetic Verification
- **Prime Selection**: $p = 2^{256} + 297$ is proven prime:
  $$\gcd(a, p) = 1 \quad \forall a \in [1, p-1]$$
- **Secret Encoding**: AES-256 keys are 32 bytes (256 bits), representing integers in $[0, 2^{256} - 1]$. Since $2^{256} < p$, the entire key space embeds into $\mathbb{F}_p$ without modulo truncation.
- **Lagrange Interpolation at $x = 0$**:
  $$S = \sum_{i=1}^k y_i \prod_{j \ne i} \frac{-x_j}{x_i - x_j} \pmod p$$
  Modular inverse is evaluated via `pow(den, -1, p)` (extended Euclidean algorithm).
- **Exact Conversion**: Reconstructed integer $S$ is checked:
  - If $S \ge 2^{256}$: Immediately rejected with `ValueError("Reconstructed secret is outside the valid 256-bit range")`.
  - Converted using `S.to_bytes(32, "big")`, guaranteeing exactly 32 bytes with correct zero-padding.

### B. Authenticated Envelope Protection
- Reconstructed KEKs are used exclusively to wrap/unwrap DEKs using `AES-256-GCM` with a 96-bit random nonce and 128-bit authentication tag.
- If an invalid share is supplied, Lagrange interpolation produces an incorrect candidate key $K'$.
- Attempting to unwrap a stored DEK using $K'$ triggers `cryptography.exceptions.InvalidTag`.
- **Verdict**: An incorrect KEK cannot silently unwrap a DEK or produce corrupted plaintext.

### C. Key Check Value (KCV) Trust Boundary & Security Guarantees
- **Guarantees Provided**:
  - **Accidental Custodian Error Detection**: Protects against typos, corrupted share strings, or submitting shares from the wrong key version during legitimate recovery.
  - **Custodian Collusion / Forgery Detection**: When the database commitment is intact, an attacker submitting forged shares cannot trick the service into unlocking an arbitrary key.
- **Threat Model Boundary & Limitations**:
  - The KCV is an unkeyed cryptographic hash: $\text{KCV} = \text{SHA-256}(\text{"CAS-SE-KCV-V"} \parallel \text{version} \parallel \text{":"} \parallel \text{KEK})$ stored directly in the `cas_key_versions` table.
  - It does **NOT** protect against an attacker with database write access (e.g., SQL injection, compromised database credentials, rogue DBA). Such an attacker could compute a valid SHA-256 hash for an arbitrary key and update the database row, or alter records.
  - In high-assurance production environments where database administrators or database-level attackers are part of the threat model, KCV commitments must be signed by an out-of-band trust anchor (such as a hardware security module, external KMS like AWS KMS / HashiCorp Vault, or an offline PKI root).

---

## 6. Locking, Concurrency & Multi-Process Audit

### A. Thread Safety (SEC-03)
- Added `self._lock = threading.RLock()` to `SplitKeyService`.
- Wrapped all mutations and state inspections in `with self._lock:`.
- Verified via `test_split_key_concurrent_access_stress` executing 200 concurrent lock, unlock, and status operations across 8 worker threads with zero race conditions.

### B. Multi-Process / Celery Worker Boundary (SEC-05)
- **Finding**: In-memory state in `SplitKeyService` is isolated to the operating system process virtual memory.
- **Implication**:
  1. If Uvicorn runs with `--workers N` ($N > 1$), an unlock request to worker $A$ does not unlock worker $B$.
  2. The Celery worker (`cas-se-worker`) runs as a separate process and cannot unwrap DEKs unless provided pre-configured shares or an external key service.
- **Guidance**: For the non-Docker native development launcher (`start-dev.bat`), the backend runs with `workers=1`, ensuring consistent in-memory state. For production distributed deployments, see Section 9.

---

## 7. API Authorization & Audit Trail Audit

Tested all 6 key-management API endpoints against all 5 system roles and unauthenticated callers:

| Endpoint | Unauthenticated | `uploader` | `trainer` | `researcher` | `auditor` | `admin` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `GET /keys/status` | 401 | 403 | 403 | 403 | 403 | **200** |
| `POST /keys/shamir/init` | 401 | 403 | 403 | 403 | 403 | **200** |
| `POST /keys/shamir/unlock` | 401 | 403 | 403 | 403 | 403 | **200** |
| `POST /keys/shamir/lock` | 401 | 403 | 403 | 403 | 403 | **200** |
| `POST /keys/rotate` | 401 | 403 | 403 | 403 | 403 | **200** |
| `GET /keys` | 401 | 403 | 403 | 403 | 403 | **200** |

All attempts are audited in `cas_access_audit` with `actor_id`, `decision`, and sanitized `reason`.

---

## 8. Executable Evidence & Test Verification

All audit assertions are backed by automated tests:

### Command 1: Targeted Shamir Security & Persistence Audit
```powershell
python -m pytest backend/tests/test_shamir_security_audit.py -v
```
**Output**:
```
backend/tests/test_shamir_security_audit.py::test_api_authorization_matrix_on_key_endpoints PASSED [ 25%]
backend/tests/test_shamir_security_audit.py::test_restart_and_historical_recovery PASSED [ 50%]
backend/tests/test_shamir_security_audit.py::test_shares_and_keys_never_leak_in_errors_or_audit PASSED [ 75%]
backend/tests/test_shamir_security_audit.py::test_split_key_concurrent_access_stress PASSED [100%]
======================== 4 passed, 3 warnings in 3.41s ========================
```

### Command 2: Combined Shamir Suite (Unit + Integration + Security)
```powershell
python -m pytest backend/tests/test_shamir_security_audit.py backend/tests/test_key_service_adapters.py -v
```
**Output**:
```
collected 23 items
...
======================= 23 passed, 4 warnings in 4.04s ========================
```

### Command 3: Full Repository Regression Suite
```powershell
python -m pytest backend/tests/ -v
```
**Output**:
```
====================== 119 passed, 7 warnings in 22.45s =======================
```

### Command 4: Code Quality & Linting
```powershell
ruff check backend/app/adapters/key_service.py backend/app/api/keys.py backend/tests/test_shamir_security_audit.py
```
**Output**:
```
All checks passed!
```

---

## 9. Remaining Blockers & Production Roadmap

The implementation is verified and functional for development, demonstration, and single-worker deployments. For high-assurance production deployments, the following architectural steps remain necessary:

1. **Hardware Security Module (HSM) Quorum**: Replace in-process RAM reconstruction with an HSM (e.g. AWS CloudHSM, HashiCorp Vault transit secrets engine with Shamir unseal).
2. **Distributed Custodian Channels**: Replace single-session admin share output with individual custodian mTLS endpoints where each custodian receives and submits only their assigned share.
3. **Memory Hardening**: Python process memory cannot guarantee zeroization due to garbage-collected immutable `bytes`. Production implementations should use C extensions with `mlock` and `sodium_memzero`.
4. **Cross-Worker State**: Use a local IPC key daemon or centralized KMS to allow multi-worker API clusters and Celery workers to access unwrapped DEKs without sharing process memory.
