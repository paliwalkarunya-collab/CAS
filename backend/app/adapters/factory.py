"""Adapter construction for the CAS-SE integration boundary.

CAS-SE owns its orchestration layer, not an organization's infrastructure.
This module keeps the reference adapters convenient while letting an adopter
configure factories from their integration package. Factories receive the
immutable application settings and must return an implementation of the
relevant protocol; this makes configuration explicit and testable rather than
requiring edits in API route handlers.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from app.adapters.identity import IdentityAdapter
from app.adapters.key_service import EnvVarKeyService, KeyServiceAdapter, SplitKeyService
from app.adapters.storage import LocalFileAdapter, MinIOAdapter, StorageAdapter

if TYPE_CHECKING:
    from app.core.config import Settings


class AdapterConfigurationError(RuntimeError):
    """Raised when an adapter factory cannot be loaded or violates its contract."""


def _load_factory(path: str) -> Callable[[Settings], Any]:
    """Load an integration factory from ``package.module:callable`` syntax."""
    module_name, separator, attribute = path.partition(":")
    if not separator or not module_name or not attribute:
        raise AdapterConfigurationError("Adapter factory must use 'package.module:callable' syntax")
    try:
        factory = getattr(importlib.import_module(module_name), attribute)
    except (ImportError, AttributeError) as exc:
        raise AdapterConfigurationError(
            f"Unable to load configured adapter factory {path!r}"
        ) from exc
    if not callable(factory):
        raise AdapterConfigurationError(f"Configured adapter factory {path!r} is not callable")
    # ``Settings`` is intentionally imported only for type checking to avoid
    # a configuration/import cycle, so use ``Any`` in this runtime cast.
    return cast(Callable[[Any], Any], factory)


def _from_factory(path: str, settings: Settings, protocol: Any, kind: str) -> Any:
    try:
        adapter = _load_factory(path)(settings)
    except AdapterConfigurationError:
        raise
    except Exception as exc:
        raise AdapterConfigurationError(f"Configured {kind} adapter factory failed") from exc
    if not isinstance(adapter, protocol):
        raise AdapterConfigurationError(
            f"Configured {kind} adapter does not implement the {protocol.__name__} contract"
        )
    return adapter


def build_storage_adapter(settings: Settings) -> StorageAdapter:
    """Build the configured ciphertext-storage adapter once at application startup."""
    if settings.storage_adapter_factory:
        return cast(
            StorageAdapter,
            _from_factory(settings.storage_adapter_factory, settings, StorageAdapter, "storage"),
        )
    if settings.storage_adapter == "local":
        return LocalFileAdapter(settings.local_storage_path)
    if settings.storage_adapter == "minio":
        return MinIOAdapter(
            endpoint_url=settings.object_storage_endpoint,
            access_key=settings.object_storage_access_key,
            secret_key=settings.object_storage_secret_key,
            bucket_name=settings.object_storage_bucket,
            use_ssl=settings.object_storage_use_ssl,
        )
    raise AdapterConfigurationError(
        f"Unknown storage adapter {settings.storage_adapter!r}; configure STORAGE_ADAPTER_FACTORY"
    )


def build_key_service(settings: Settings) -> KeyServiceAdapter:
    """Build the configured versioned KEK adapter once at application startup."""
    if settings.key_service_adapter_factory:
        return cast(
            KeyServiceAdapter,
            _from_factory(
                settings.key_service_adapter_factory, settings, KeyServiceAdapter, "key-service"
            ),
        )
    if settings.key_service_adapter == "env":
        return EnvVarKeyService()
    if settings.key_service_adapter == "split":
        return SplitKeyService(
            shares=settings.split_key_shares,
            threshold=settings.split_key_threshold,
        )
    raise AdapterConfigurationError(
        f"Unknown key-service adapter {settings.key_service_adapter!r}; "
        "configure KEY_SERVICE_ADAPTER_FACTORY"
    )


def build_identity_adapter(settings: Settings) -> IdentityAdapter | None:
    """Build an external identity adapter, or ``None`` for reference JWT auth."""
    if settings.identity_adapter == "builtin" and not settings.identity_adapter_factory:
        return None
    if settings.identity_adapter_factory:
        return cast(
            IdentityAdapter,
            _from_factory(settings.identity_adapter_factory, settings, IdentityAdapter, "identity"),
        )
    raise AdapterConfigurationError(
        f"Unknown identity adapter {settings.identity_adapter!r}; "
        "configure IDENTITY_ADAPTER_FACTORY"
    )
