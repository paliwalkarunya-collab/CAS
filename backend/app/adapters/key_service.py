"""
CAS-SE Key Service Adapter Interface

Defines the pluggable Key Encryption Key (KEK) backend contract.
Organizations plug in their own KMS (AWS KMS, HashiCorp Vault, HSM) by
implementing this protocol.

Envelope encryption model:
  - Each data record is encrypted with a fresh random DEK (AES-256).
  - The DEK is wrapped (encrypted) with the current KEK version.
  - Only the wrapped DEK is stored -- never the raw DEK.
  - KEK rotation rewraps all stored DEKs without re-encrypting payloads.
"""

from __future__ import annotations

import base64
import os
import threading
from typing import Any, Protocol, runtime_checkable


class KeyServiceLockedError(RuntimeError):
    """Raised when an operation requiring the KEK is attempted on a locked KeyService."""


@runtime_checkable
class KeyServiceAdapter(Protocol):
    """
    Pluggable Key Encryption Key (KEK) backend protocol.

    Implementations MUST:
    - Never expose raw KEK bytes in logs, API responses, or exceptions.
    - Support versioned KEKs for rotation.
    - Be thread-safe.
    """

    def wrap_dek(self, dek: bytes) -> tuple[str, int]: ...

    def unwrap_dek(self, wrapped_dek: str, version: int) -> bytes: ...

    def current_kek_version(self) -> int: ...

    def rotate_kek(self) -> int | tuple[bytes, int]: ...

    def is_unlocked(self) -> bool: ...

    def get_status(self) -> dict[str, Any]: ...


# ---------------------------------------------------------------------------
# Reference Implementation 1: EnvVarKeyService (development / demo)
# ---------------------------------------------------------------------------


class EnvVarKeyService:
    """
    Reads the KEK from an environment variable.

    FOR DEVELOPMENT AND DEMO ONLY.
    In production, use an adapter backed by AWS KMS, HashiCorp Vault, or an HSM.

    Environment variables:
      CAS_KEK_V<version>=<base64-encoded 32-byte key>
      CAS_KEK_CURRENT_VERSION=<int>

    Example:
      CAS_KEK_V1=$(python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())")
      CAS_KEK_CURRENT_VERSION=1
    """

    def __init__(self) -> None:
        self._versions: dict[int, bytes] = {}
        self._current_version: int = 0
        self._load_from_env()

    def _load_from_env(self) -> None:
        """Load all CAS_KEK_V<n> variables from the environment."""
        try:
            from dotenv import find_dotenv, load_dotenv

            load_dotenv(find_dotenv())
        except ImportError:
            pass

        current_str = os.environ.get("CAS_KEK_CURRENT_VERSION", "1")
        try:
            self._current_version = int(current_str)
        except ValueError as e:
            raise OSError("CAS_KEK_CURRENT_VERSION must be an integer") from e

        # Scan for all version keys
        for key, value in os.environ.items():
            if key.startswith("CAS_KEK_V") and key[9:].isdigit():
                version = int(key[9:])
                try:
                    raw = base64.b64decode(value)
                except Exception as e:
                    raise OSError(f"Could not decode KEK env var {key}: {e}") from e
                if len(raw) != 32:
                    raise OSError(f"KEK in {key} must be exactly 32 bytes; got {len(raw)}")
                self._versions[version] = raw

        if self._current_version not in self._versions:
            raise OSError(
                f"CAS_KEK_V{self._current_version} is not set or not decodable. "
                'Generate one with: python -c "'
                'import base64,os; print(base64.b64encode(os.urandom(32)).decode())"'
            )

    def is_unlocked(self) -> bool:
        return True

    def get_status(self) -> dict[str, Any]:
        return {
            "adapter": "env",
            "is_unlocked": True,
            "threshold": 1,
            "total_shares": 1,
            "current_version": self._current_version,
            "shares_provided_count": 1,
            "recovered_versions": sorted(self._versions.keys()),
        }

    def get_current_kek(self) -> tuple[bytes, int]:
        """Legacy development-only method. Production callers use wrap_dek."""
        return self._versions[self._current_version], self._current_version

    def get_kek_by_version(self, version: int) -> bytes:
        if version not in self._versions:
            raise KeyError(f"KEK version {version} not found")
        return self._versions[version]

    def rotate_kek(self) -> tuple[bytes, int]:
        new_version = self._current_version + 1
        new_kek = os.urandom(32)
        self._versions[new_version] = new_kek
        self._current_version = new_version
        # NOTE: In a real service, persist the new KEK to the KMS/Vault here.
        return new_kek, new_version

    def current_kek_version(self) -> int:
        return self._current_version

    def get_kcv(self, version: int) -> str | None:
        import hashlib
        kek = self._versions.get(version)
        if kek is not None:
            return hashlib.sha256(f"CAS-SE-KCV-V{version}:".encode() + kek).hexdigest()
        return None

    def wrap_dek(self, dek: bytes) -> tuple[str, int]:
        from app.services.crypto import wrap_dek

        wrapped = wrap_dek(dek, self._versions[self._current_version], self._current_version)
        return wrapped.wrapped_dek_b64, wrapped.kek_version

    def unwrap_dek(self, wrapped_dek: str, version: int) -> bytes:
        from app.services.crypto import unwrap_dek

        return unwrap_dek(wrapped_dek, self.get_kek_by_version(version))


# ---------------------------------------------------------------------------
# Reference Implementation 2: SplitKeyService (academic simulation)
# ---------------------------------------------------------------------------

_SHAMIR_PRIME = 2**256 + 297  # Smallest prime strictly greater than 2**256


class SplitKeyService:
    """
    Simulated 2-of-3 (or k-of-n) Shamir Secret Sharing key service.

    ACADEMIC DEMONSTRATION & CONTROLLED SIMULATION ONLY.
    In production, use independently held custodian endpoints or a hardware HSM.

    Finite-field arithmetic is evaluated over GF(p) with p = 2**256 + 297.
    Reconstruction recovers a 256-bit integer and encodes it as exactly 32 bytes.

    Lifecycle:
    - If initialized with at least `threshold` shares, immediately unlocks.
    - If initialized without shares, starts in locked state (fail-closed).
    - Can be unlocked via `unlock(shares)` or locked via `lock()`.
    - Key rotation generates new KEK material, creates a fresh polynomial,
      provisions new shares, and retains historical keys in memory.
    """

    def __init__(
        self,
        shares: list[str] | None = None,
        threshold: int = 2,
        total: int = 3,
        current_version: int = 1,
    ) -> None:
        """
        :param shares: Optional list of share strings in format "x-hex_y".
        :param threshold: Minimum shares needed to reconstruct the KEK (default 2).
        :param total: Total number of shares to provision (default 3).
        :param current_version: Starting KEK version number.
        """
        if threshold < 2:
            raise ValueError(f"SplitKeyService threshold must be >= 2; got {threshold}")
        if total < threshold:
            raise ValueError(
                f"SplitKeyService total shares ({total}) must be >= threshold ({threshold})"
            )

        self._threshold = threshold
        self._total = total
        self._current_version = current_version
        self._shares: list[str] = []
        self._historic: dict[int, bytes] = {}
        self._historic_shares: dict[int, list[str]] = {}
        self._kcv: dict[int, str] = {}
        self._kek: bytes | None = None
        self._is_unlocked: bool = False
        self._last_generated_shares: list[str] | None = None
        self._lock = threading.RLock()

        if shares is not None and len(shares) > 0:
            if len(shares) < self._threshold:
                raise ValueError(
                    f"SplitKeyService requires at least {self._threshold} shares to reconstruct "
                    f"the KEK; received {len(shares)}."
                )
            self._kek = self._reconstruct(shares)
            self._historic[self._current_version] = self._kek
            self._kcv[self._current_version] = self.compute_kcv(self._kek, self._current_version)
            self._shares = list(shares)
            self._is_unlocked = True

    @staticmethod
    def compute_kcv(kek: bytes, version: int) -> str:
        """
        Compute domain-separated cryptographic Key Check Value (KCV).

        TRUST BOUNDARY & SECURITY GUARANTEES:
        - Accidental Corrupted Share Detection: Protects against custodian typos,
          corrupted transmissions, or submitting shares for the wrong key version.
        - Custodian Collusion / Tampering: When the database commitment is intact,
          an attacker submitting forged shares cannot trick the service into unlocking
          a mismatched key.
        - Threat Model Limitation (Database Compromise):
          This KCV is an unkeyed SHA-256 digest stored directly in the application's
          relational database (cas_key_versions). An attacker with direct write access
          to the database can replace both the KCV commitment and key metadata, or
          tamper with records. Protecting against a database-level attacker requires an
          out-of-band trust anchor (such as an authenticated Hardware Security Module,
          AWS KMS, HashiCorp Vault, or offline signed certificate chain).
        """
        import hashlib

        return hashlib.sha256(f"CAS-SE-KCV-V{version}:".encode() + kek).hexdigest()

    def get_kcv(self, version: int) -> str | None:
        """Return Key Check Value (KCV) commitment for specified key version."""
        with self._lock:
            return self._kcv.get(version)

    def is_unlocked(self) -> bool:
        """Return True if the active encryption KEK is currently reconstructed and held in memory."""
        with self._lock:
            return (
                self._is_unlocked
                and self._kek is not None
                and self._current_version in self._historic
            )

    def set_current_version(self, version: int) -> None:
        """
        Synchronize the active KEK version from trusted persisted metadata.
        Does NOT unlock the version if its key material is not already in memory.
        """
        with self._lock:
            self._current_version = version
            if version in self._historic:
                self._kek = self._historic[version]
                self._is_unlocked = True
            else:
                self._kek = None
                self._is_unlocked = False

    def unlock(
        self,
        shares: list[str],
        version: int | None = None,
        expected_kcv: str | None = None,
        require_kcv: bool = False,
    ) -> tuple[bytes, int]:
        """
        Reconstruct and activate the KEK from threshold shares.

        :param shares: At least `threshold` share strings in format "x-hex_y".
        :param version: Target version to unlock (defaults to current_version).
        :param expected_kcv: Optional expected Key Check Value to verify reconstructed key integrity.
        :param require_kcv: If True, fails closed if no expected KCV is registered or provided.
        :returns: (reconstructed_kek_bytes, target_version)
        :raises ValueError: If shares are malformed, duplicate, insufficient, or fail KCV validation.
        """
        if not shares or len(shares) < self._threshold:
            raise ValueError(
                f"SplitKeyService requires at least {self._threshold} shares "
                f"to reconstruct the KEK; got {len(shares) if shares else 0}"
            )

        target_version = version if version is not None else self._current_version
        reconstructed = self._reconstruct(shares)

        # Cryptographic Key Check Value validation if expected or previously registered
        target_kcv = expected_kcv or self._kcv.get(target_version)
        if require_kcv and not target_kcv:
            raise ValueError(
                f"Key Check Value (KCV) commitment is required to unlock version {target_version}."
            )
        if target_kcv:
            import hmac

            actual_kcv = self.compute_kcv(reconstructed, target_version)
            if not hmac.compare_digest(actual_kcv, target_kcv):
                raise ValueError(
                    f"Reconstructed KEK failed Key Check Value (KCV) verification for version {target_version}; "
                    f"shares are corrupted, forged, or belong to a different key"
                )

        with self._lock:
            self._historic[target_version] = reconstructed
            self._kcv[target_version] = target_kcv or self.compute_kcv(reconstructed, target_version)

            # Active encryption key handling:
            # Unlocking a historical version (target_version < self._current_version) must NEVER
            # downgrade the active encryption version.
            # Only update active key if unlocking the current active version or a higher version.
            if target_version >= self._current_version:
                self._kek = reconstructed
                self._current_version = target_version
                self._shares = list(shares)
                self._is_unlocked = True
            elif self._current_version in self._historic:
                # If current version is already unlocked, keep it active
                self._kek = self._historic[self._current_version]
                self._is_unlocked = True
            else:
                # Historical version is now available in _historic, but active version is still locked
                self._kek = None
                self._is_unlocked = False

        return reconstructed, target_version

    def lock(self) -> None:
        """Lock the service and wipe all in-memory KEK material and historical references."""
        with self._lock:
            self._kek = None
            self._is_unlocked = False
            self._shares.clear()
            self._historic.clear()

    def get_status(self) -> dict[str, Any]:
        """Return safe, non-sensitive operational metadata."""
        with self._lock:
            return {
                "adapter": "split",
                "is_unlocked": self.is_unlocked(),
                "threshold": self._threshold,
                "total_shares": self._total,
                "current_version": self._current_version,
                "shares_provided_count": len(self._shares) if self.is_unlocked() else 0,
                "recovered_versions": sorted(self._historic.keys()),
            }

    def _reconstruct(self, shares: list[str]) -> bytes:
        """
        Reconstruct the 32-byte KEK from threshold shares via Lagrange interpolation.
        Validates:
          - Share count >= threshold
          - Format: "x-hex_y"
          - 1 <= x < p
          - 0 <= y < p
          - No duplicate x coordinates
          - Reconstructed integer in [0, 2**256 - 1]
        """
        if not shares or len(shares) < self._threshold:
            raise ValueError(
                f"SplitKeyService requires at least {self._threshold} shares "
                f"to reconstruct the KEK; got {len(shares) if shares else 0}"
            )

        points: list[tuple[int, int]] = []
        seen_x: set[int] = set()
        p = _SHAMIR_PRIME

        for s in shares:
            if not isinstance(s, str) or "-" not in s:
                raise ValueError("Malformed split-key share format (missing '-'); expected 'x-hex_y'")

            x_str, y_str = s.split("-", 1)
            try:
                x = int(x_str)
            except ValueError as e:
                raise ValueError(
                    f"Invalid share x-coordinate {x_str!r}: must be an integer"
                ) from e

            if x <= 0 or x >= p:
                raise ValueError(
                    f"Share x-coordinate out of valid range (1 <= x < p): {x}"
                )

            if x in seen_x:
                raise ValueError(
                    f"Duplicate share x-coordinate {x} detected; shares must be distinct"
                )
            seen_x.add(x)

            try:
                y = int(y_str, 16)
            except ValueError as e:
                raise ValueError(f"Invalid share y-coordinate hex format at index {x}") from e

            if y < 0 or y >= p:
                raise ValueError(f"Share y-coordinate out of field range at index {x} (must be < p)")

            points.append((x, y))

        if len(points) < self._threshold:
            raise ValueError(
                f"Need at least {self._threshold} distinct shares; got {len(points)}"
            )

        # Reconstruct using the first threshold points
        recovered = self._interpolate_secret(points[: self._threshold], p)

        # If extra shares were supplied, verify polynomial consistency across all combinations
        if len(points) > self._threshold:
            import itertools

            for subset in itertools.combinations(points, self._threshold):
                sub_recovered = self._interpolate_secret(list(subset), p)
                if sub_recovered != recovered:
                    raise ValueError(
                        "Inconsistent shares detected: submitted shares do not interpolate to the same polynomial"
                    )

        if recovered < 0 or recovered >= (1 << 256):
            raise ValueError(
                "Reconstructed secret is outside the valid 256-bit range; "
                "shares may be corrupted, forged, or inconsistent"
            )

        raw = recovered.to_bytes(32, "big")
        if len(raw) != 32:
            raise ValueError(f"Reconstructed KEK must be exactly 32 bytes; got {len(raw)}")
        return raw

    @staticmethod
    def _interpolate_secret(points: list[tuple[int, int]], p: int) -> int:
        recovered = 0
        for i, (xi, yi) in enumerate(points):
            num, den = 1, 1
            for j, (xj, _) in enumerate(points):
                if i == j:
                    continue
                num = (num * (-xj)) % p
                den = (den * (xi - xj)) % p
            lagrange_coeff = (num * pow(den, -1, p)) % p
            recovered = (recovered + yi * lagrange_coeff) % p
        return recovered

    def get_current_kek(self) -> tuple[bytes, int]:
        with self._lock:
            active_kek = self._historic.get(self._current_version) or self._kek
            if active_kek is None or not self.is_unlocked():
                raise KeyServiceLockedError(
                    f"SplitKeyService is locked; active KEK version {self._current_version} "
                    f"requires 2-of-3 threshold shares to reconstruct KEK."
                )
            return active_kek, self._current_version

    def get_kek_by_version(self, version: int) -> bytes:
        with self._lock:
            if version in self._historic:
                return self._historic[version]
            if version == self._current_version and self._kek is not None:
                return self._kek
            if not self._is_unlocked and len(self._historic) == 0:
                raise KeyServiceLockedError(
                    f"SplitKeyService is locked; cannot retrieve KEK version {version}."
                )
            raise KeyError(f"Split-key KEK version {version} not available")

    def rotate_kek(self) -> tuple[bytes, int]:
        """
        Generate fresh KEK material, provision new shares, and re-split.
        Preserves the previous version KEK in _historic so DEKs can be rewrapped.
        """
        with self._lock:
            if not self.is_unlocked():
                raise KeyServiceLockedError("Cannot rotate KEK while SplitKeyService is locked.")

            old_version = self._current_version
            old_kek = self._kek
            if old_kek is not None:
                self._historic[old_version] = old_kek
                self._kcv[old_version] = self.compute_kcv(old_kek, old_version)

            new_version = self._current_version + 1
            new_kek = os.urandom(32)
            new_shares = self.generate_shares(
                new_kek.hex(), total=self._total, threshold=self._threshold
            )

            self._historic[new_version] = new_kek
            self._historic_shares[new_version] = new_shares
            self._kcv[new_version] = self.compute_kcv(new_kek, new_version)
            self._last_generated_shares = new_shares
            self._kek = new_kek
            self._current_version = new_version
            self._shares = new_shares[: self._threshold]

            return new_kek, new_version

    def init_new_key(
        self, total: int | None = None, threshold: int | None = None
    ) -> tuple[int, list[str]]:
        """
        Bootstrap a fresh 256-bit KEK, split into shares, and unlock in memory.
        Returns (version, list_of_shares).
        """
        with self._lock:
            if total is not None:
                self._total = total
            if threshold is not None:
                self._threshold = threshold
            if self._total < self._threshold:
                raise ValueError(
                    f"Total shares ({self._total}) must be >= threshold ({self._threshold})"
                )

            new_kek = os.urandom(32)
            shares = self.generate_shares(new_kek.hex(), total=self._total, threshold=self._threshold)

            self._current_version = 1
            self._historic = {1: new_kek}
            self._historic_shares = {1: shares}
            self._kcv[1] = self.compute_kcv(new_kek, 1)
            self._last_generated_shares = shares
            self._kek = new_kek
            self._shares = shares[: self._threshold]
            self._is_unlocked = True

            return 1, shares

    def get_last_generated_shares(self) -> list[str] | None:
        """Return shares provisioned during the most recent rotation or init (if any)."""
        with self._lock:
            return self._last_generated_shares

    def current_kek_version(self) -> int:
        with self._lock:
            return self._current_version

    def wrap_dek(self, dek: bytes) -> tuple[str, int]:
        from app.services.crypto import wrap_dek

        kek, version = self.get_current_kek()
        wrapped = wrap_dek(dek, kek, version)
        return wrapped.wrapped_dek_b64, wrapped.kek_version

    def unwrap_dek(self, wrapped_dek: str, version: int) -> bytes:
        from app.services.crypto import unwrap_dek

        return unwrap_dek(wrapped_dek, self.get_kek_by_version(version))

    @staticmethod
    def generate_shares(secret_hex: str, total: int = 3, threshold: int = 2) -> list[str]:
        """
        Split a hex-encoded secret into `total` shares using Shamir scheme over GF(p).
        Returns a list of share strings: "x-hex_y".
        """
        import secrets

        if threshold < 2:
            raise ValueError(f"Threshold must be at least 2; got {threshold}")
        if total < threshold:
            raise ValueError(f"Total ({total}) must be >= threshold ({threshold})")

        try:
            secret_bytes = bytes.fromhex(secret_hex)
        except ValueError as e:
            raise ValueError(f"Secret must be valid hexadecimal: {e}") from e

        if len(secret_bytes) != 32:
            raise ValueError(
                f"Secret must be exactly 32 bytes (64 hex chars); got {len(secret_bytes)}"
            )

        secret_int = int.from_bytes(secret_bytes, "big")
        p = _SHAMIR_PRIME
        if secret_int >= p:
            raise ValueError("Secret must be less than field prime")

        # Generate polynomial coefficients: f(x) = secret + a1*x + ... + a_{k-1}*x^{k-1}
        # Ensure highest degree coefficient is strictly non-zero
        coeffs = [secret_int]
        for idx in range(threshold - 1):
            c = (
                secrets.randbelow(p - 1) + 1
                if idx == threshold - 2
                else secrets.randbelow(p)
            )
            coeffs.append(c)

        shares: list[str] = []
        for x in range(1, total + 1):
            y = 0
            x_pow = 1
            for coeff in coeffs:
                y = (y + coeff * x_pow) % p
                x_pow = (x_pow * x) % p
            shares.append(f"{x}-{y:x}")

        return shares
