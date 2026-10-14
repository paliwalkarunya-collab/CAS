"""
CAS-SE Storage Adapter Interface

Defines the pluggable storage backend contract. Organizations implement this
protocol for their own object storage (Azure Blob, GCS, custom) or use the
provided MinIOAdapter / LocalFileAdapter references.

Never store raw plaintext image payloads -- only ciphertext blobs.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Protocol, runtime_checkable

import boto3
from botocore.exceptions import ClientError


@runtime_checkable
class StorageAdapter(Protocol):
    """
    Pluggable object-storage backend protocol.

    All implementations MUST:
    - Accept arbitrary binary ciphertext blobs.
    - Use randomised, unpredictable object keys (never expose original filenames).
    - Keep buckets/containers private (no public read).
    - Return the canonical object key/URI on `put_object`.
    """

    def put_object(self, key: str, data: bytes) -> str:
        """
        Upload ciphertext `data` under `key`.
        Returns the canonical URI / key that can later be passed to `get_object`.
        """
        ...

    def get_object(self, key: str) -> bytes:
        """Retrieve ciphertext blob by key. Raises KeyError if not found."""
        ...

    def delete_object(self, key: str) -> None:
        """Permanently delete an object. Raises KeyError if not found."""
        ...

    def health_check(self) -> bool:
        """Return True if the storage backend is reachable."""
        ...


# ---------------------------------------------------------------------------
# Reference Implementation 1: MinIO / AWS S3 (boto3 / S3 API)
# ---------------------------------------------------------------------------


class MinIOAdapter:
    """
    Reference storage adapter using the S3-compatible API (boto3).

    Works with MinIO (local dev), AWS S3, and any S3-compatible store.
    Configure via environment variables -- see .env.example.
    """

    def __init__(
        self,
        endpoint_url: str,
        access_key: str,
        secret_key: str,
        bucket_name: str,
        region: str = "us-east-1",
        use_ssl: bool = False,
    ) -> None:
        self._bucket = bucket_name
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
            use_ssl=use_ssl,
        )
        self._ensure_bucket()

    def _ensure_bucket(self) -> None:
        """Create the bucket if it does not exist."""
        try:
            self._client.head_bucket(Bucket=self._bucket)
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code in ("404", "NoSuchBucket"):
                self._client.create_bucket(Bucket=self._bucket)
            else:
                raise

    def put_object(self, key: str, data: bytes) -> str:
        self._client.put_object(Bucket=self._bucket, Key=key, Body=data)
        return key

    def get_object(self, key: str) -> bytes:
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key)
            return bytes(response["Body"].read())
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code in ("404", "NoSuchKey"):
                raise KeyError(f"Object not found: {key}") from exc
            raise

    def delete_object(self, key: str) -> None:
        self._client.delete_object(Bucket=self._bucket, Key=key)

    def health_check(self) -> bool:
        try:
            self._client.head_bucket(Bucket=self._bucket)
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Reference Implementation 2: Local filesystem (development / testing only)
# ---------------------------------------------------------------------------


class LocalFileAdapter:
    """
    Fallback storage adapter that writes ciphertext blobs to the local filesystem.

    FOR DEVELOPMENT AND TESTING ONLY -- never use in production.
    Blobs are stored as binary files under `base_dir / key`.
    """

    def __init__(self, base_dir: str | Path) -> None:
        self._base = Path(base_dir)
        self._base.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        # Prevent path traversal -- only allow safe key characters
        base = self._base.resolve()
        safe_key = key.replace("/", os.sep)
        resolved = (base / safe_key).resolve()
        if not resolved.is_relative_to(base) or resolved == base:
            raise ValueError(f"Path traversal detected in key: {key!r}")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        return resolved

    def put_object(self, key: str, data: bytes) -> str:
        self._path(key).write_bytes(data)
        return key

    def get_object(self, key: str) -> bytes:
        p = self._path(key)
        if not p.exists():
            raise KeyError(f"Object not found: {key}")
        return p.read_bytes()

    def delete_object(self, key: str) -> None:
        p = self._path(key)
        if not p.exists():
            raise KeyError(f"Object not found: {key}")
        p.unlink()

    def health_check(self) -> bool:
        return self._base.exists() and self._base.is_dir()


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def generate_object_key(prefix: str = "envelopes") -> str:
    """
    Generate a randomised, unpredictable object key.
    Never derive the key from the original filename or any sensitive value.
    """
    return f"{prefix}/{uuid.uuid4().hex}/{uuid.uuid4().hex}"
