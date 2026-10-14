"""Tests for StorageAdapter interface and LocalFileAdapter."""

from __future__ import annotations

import pytest

from app.adapters.storage import LocalFileAdapter, StorageAdapter, generate_object_key


def test_storage_adapter_protocol_compliance(tmp_path: pytest.TempPathFactory) -> None:
    adapter = LocalFileAdapter(str(tmp_path))
    assert isinstance(adapter, StorageAdapter)


def test_local_file_adapter_crud(tmp_path: pytest.TempPathFactory) -> None:
    adapter = LocalFileAdapter(str(tmp_path))
    key = "test/envelopes/sample.bin"
    payload = b"encrypted_ciphertext_sample_bytes"

    # Put
    stored_key = adapter.put_object(key, payload)
    assert stored_key == key

    # Get
    retrieved = adapter.get_object(key)
    assert retrieved == payload

    # Delete
    adapter.delete_object(key)
    with pytest.raises(KeyError):
        adapter.get_object(key)


def test_local_file_adapter_key_not_found(tmp_path: pytest.TempPathFactory) -> None:
    adapter = LocalFileAdapter(str(tmp_path))
    with pytest.raises(KeyError):
        adapter.get_object("nonexistent.bin")

    with pytest.raises(KeyError):
        adapter.delete_object("nonexistent.bin")


def test_local_file_adapter_health_check(tmp_path: pytest.TempPathFactory) -> None:
    adapter = LocalFileAdapter(str(tmp_path))
    assert adapter.health_check() is True


def test_local_file_adapter_path_traversal_detection(tmp_path: pytest.TempPathFactory) -> None:
    adapter = LocalFileAdapter(str(tmp_path))
    with pytest.raises(ValueError, match="Path traversal detected"):
        adapter.put_object("../../secret.bin", b"evil")


def test_generate_object_key() -> None:
    key1 = generate_object_key("custom_prefix")
    key2 = generate_object_key("custom_prefix")

    assert key1.startswith("custom_prefix/")
    assert key2.startswith("custom_prefix/")
    assert key1 != key2


def test_minio_adapter_crud(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import MagicMock

    from botocore.exceptions import ClientError

    from app.adapters.storage import MinIOAdapter

    mock_client = MagicMock()
    mock_client.head_bucket.return_value = {}

    storage_bucket: dict[str, bytes] = {}

    def mock_put_object(Bucket: str, Key: str, Body: bytes):
        storage_bucket[Key] = Body
        return {}

    def mock_get_object(Bucket: str, Key: str):
        if Key not in storage_bucket:
            raise ClientError(
                {"Error": {"Code": "404", "Message": "NoSuchKey"}},
                "GetObject",
            )
        body_mock = MagicMock()
        body_mock.read.return_value = storage_bucket[Key]
        return {"Body": body_mock}

    def mock_delete_object(Bucket: str, Key: str):
        storage_bucket.pop(Key, None)
        return {}

    mock_client.put_object.side_effect = mock_put_object
    mock_client.get_object.side_effect = mock_get_object
    mock_client.delete_object.side_effect = mock_delete_object

    monkeypatch.setattr("boto3.client", lambda *args, **kwargs: mock_client)

    adapter = MinIOAdapter(
        endpoint_url="http://localhost:9000",
        access_key="minioadmin",
        secret_key="minioadmin",
        bucket_name="cas-envelopes-test",
    )
    assert isinstance(adapter, StorageAdapter)

    # Test put and get
    key = "envelopes/uuid1/uuid2"
    payload = b"encrypted_s3_data"
    adapter.put_object(key, payload)
    retrieved = adapter.get_object(key)
    assert retrieved == payload

    # Test delete
    adapter.delete_object(key)
    with pytest.raises(KeyError):
        adapter.get_object(key)

    # Test health check
    assert adapter.health_check() is True

    # Health check failure
    mock_client.head_bucket.side_effect = Exception("Connection refused")
    assert adapter.health_check() is False
