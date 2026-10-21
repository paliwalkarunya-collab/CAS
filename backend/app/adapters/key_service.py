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
from typing import Protocol, runtime_checkable


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
    Simulated 2-of-3 Shamir Secret Sharing key service.

    ACADEMIC DEMONSTRATION ONLY -- not a production key management system.
    In production, use a hardware-backed KMS or HSM.

    Simulates a scenario where the master KEK is split into 3 shares; any 2
    are sufficient to reconstruct it. Share storage and transport are outside
    the scope of this simulation -- in reality each share would be held by a
    different custodian in a separate secure system.

    Uses Shamir Secret Sharing polynomial arithmetic over GF(p) with p = 2**256 + 297.
    """

    def __init__(self, shares: list[str], threshold: int = 2) -> None:
        """
        :param shares: At least `threshold` share strings in format "x-hex_y".
        :param threshold: Minimum shares needed to reconstruct the KEK (default 2).
        """
        if len(shares) < threshold:
            raise ValueError(
                f"SplitKeyService requires at least {threshold} shares "
                f"to reconstruct the KEK; got {len(shares)}"
            )
        self._shares = shares
        self._threshold = threshold
        self._kek: bytes | None = None
        self._current_version: int = 1
        self._historic: dict[int, bytes] = {}

    def _reconstruct(self) -> bytes:
        """Reconstruct the KEK from threshold shares via Lagrange interpolation."""
        points: list[tuple[int, int]] = []
        for s in self._shares[: self._threshold]:
            try:
                x_str, y_str = s.split("-", 1)
                points.append((int(x_str), int(y_str, 16)))
            except Exception as e:
                raise ValueError(f"Malformed split-key share format: {s!r}") from e

        p = _SHAMIR_PRIME
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

        raw = recovered.to_bytes(32, "big")
        if len(raw) != 32:
            raise ValueError(f"Reconstructed KEK must be 32 bytes; got {len(raw)}")
        return raw

    def get_current_kek(self) -> tuple[bytes, int]:
        if self._kek is None:
            self._kek = self._reconstruct()
            self._historic[self._current_version] = self._kek
        return self._kek, self._current_version

    def get_kek_by_version(self, version: int) -> bytes:
        if version not in self._historic:
            raise KeyError(f"Split-key KEK version {version} not available")
        return self._historic[version]

    def rotate_kek(self) -> tuple[bytes, int]:
        """
        Generate new KEK material. In production, the new key would be
        re-split and new shares distributed to custodians.
        """
        new_version = self._current_version + 1
        new_kek = os.urandom(32)
        self._historic[new_version] = new_kek
        self._kek = new_kek
        self._current_version = new_version
        return new_kek, new_version

    def current_kek_version(self) -> int:
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
        Utility: split a hex-encoded secret into `total` shares using Shamir scheme.
        Returns a list of share strings. Used to initialise a new SplitKeyService.
        """
        import secrets

        secret_bytes = bytes.fromhex(secret_hex)
        if len(secret_bytes) != 32:
            raise ValueError(f"Secret must be 32 bytes; got {len(secret_bytes)}")

        secret_int = int.from_bytes(secret_bytes, "big")
        p = _SHAMIR_PRIME

        # Generate polynomial coefficients: f(x) = secret + a1*x + ... + a_{k-1}*x^{k-1}
        coeffs = [secret_int] + [secrets.randbelow(p) for _ in range(threshold - 1)]

        shares: list[str] = []
        for x in range(1, total + 1):
            y = 0
            x_pow = 1
            for coeff in coeffs:
                y = (y + coeff * x_pow) % p
                x_pow = (x_pow * x) % p
            shares.append(f"{x}-{y:x}")

        return shares
