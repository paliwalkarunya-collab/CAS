"""Authenticated ML job manifests.

An approved job stores a small, canonical manifest in the CAS-SE overlay.
The manifest is authenticated with a dedicated HMAC key before a worker or
data-release path accepts it. A random bearer token is not a signature and is
therefore deliberately not used here.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


class ManifestVerificationError(ValueError):
    """Raised when a persisted manifest is malformed or its MAC is invalid."""


_REQUIRED_FIELDS = {
    "job_id",
    "requester_id",
    "allowed_view",
    "envelope_ids",
    "expires_at",
    "policy_version",
}


def canonicalize_manifest(manifest: dict[str, Any]) -> bytes:
    """Create the deterministic byte representation used for HMAC signing."""
    if set(manifest) != _REQUIRED_FIELDS:
        missing = _REQUIRED_FIELDS - set(manifest)
        unexpected = set(manifest) - _REQUIRED_FIELDS
        detail = "missing required fields" if missing else "contains unexpected fields"
        if missing and unexpected:
            detail = "has an invalid field set"
        raise ManifestVerificationError(f"Manifest {detail}")
    if not isinstance(manifest["envelope_ids"], list) or not all(
        isinstance(value, str) for value in manifest["envelope_ids"]
    ):
        raise ManifestVerificationError("Manifest envelope_ids must be a list of strings")
    if manifest["allowed_view"] not in {
        "metadata_only",
        "masked_image",
        "feature_only",
        "raw_image",
    }:
        raise ManifestVerificationError("Manifest allowed_view is invalid")
    return json.dumps(
        manifest,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sign_manifest(manifest: dict[str, Any], signing_key: bytes) -> str:
    """Return an HMAC-SHA-256 hex signature for a canonical job manifest."""
    if not signing_key:
        raise ValueError("Manifest signing key must not be empty")
    return hmac.new(signing_key, canonicalize_manifest(manifest), hashlib.sha256).hexdigest()


def serialize_signed_manifest(manifest: dict[str, Any], signing_key: bytes) -> str:
    """Serialize a signed manifest for server-side persistence only."""
    return json.dumps(
        {
            "manifest": manifest,
            "signature": sign_manifest(manifest, signing_key),
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def verify_signed_manifest(serialized: str, signing_key: bytes) -> dict[str, Any]:
    """Verify a persisted manifest and return its trusted data.

    The signature is intentionally kept inside the server-side document. API
    responses expose the already-authorized manifest fields but never a bearer
    token or a reusable signing artifact.
    """
    try:
        payload = json.loads(serialized)
        manifest = payload["manifest"]
        signature = payload["signature"]
    except (TypeError, KeyError, json.JSONDecodeError) as exc:
        raise ManifestVerificationError("Persisted job manifest is malformed") from exc
    if not isinstance(manifest, dict) or not isinstance(signature, str):
        raise ManifestVerificationError("Persisted job manifest is malformed")
    expected = sign_manifest(manifest, signing_key)
    if not hmac.compare_digest(signature, expected):
        raise ManifestVerificationError("Persisted job manifest signature is invalid")
    return manifest
