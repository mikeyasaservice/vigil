"""Tenant-bound secret and object-store references for managed connectors.

Workers receive opaque references. Only the connector process resolves them,
and the configured endpoint allowlist is checked before any SDK call.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlparse

from core.agents.managed_execution import ManagedSecurityError


@dataclass(frozen=True)
class SecretBinding:
    tenant_id: str
    integration_id: str
    secret_ref: str
    endpoint: str


@dataclass(frozen=True)
class ObjectStoreBinding:
    tenant_id: str
    store_id: str
    bucket: str
    prefix: str
    endpoint: str


def _allowed(endpoint: str, allowlist: tuple[str, ...]) -> bool:
    parsed = urlparse(endpoint)
    return bool(parsed.scheme and parsed.netloc and endpoint.rstrip("/") in {item.rstrip("/") for item in allowlist})


class ManagedBindingRegistry:
    def __init__(
        self,
        secrets: Mapping[str, SecretBinding],
        stores: Mapping[str, ObjectStoreBinding],
        allowed_endpoints: tuple[str, ...],
    ) -> None:
        self._secrets = dict(secrets)
        self._stores = dict(stores)
        self._allowed_endpoints = allowed_endpoints

    def secret(self, *, tenant_id: str, integration_id: str, secret_ref: str) -> SecretBinding:
        binding = self._secrets.get(secret_ref)
        if binding is None or binding.tenant_id != tenant_id or binding.integration_id != integration_id:
            raise ManagedSecurityError("secret binding is not owned by the tenant integration")
        if not _allowed(binding.endpoint, self._allowed_endpoints):
            raise ManagedSecurityError("secret endpoint is outside the deployment allowlist")
        return binding

    def object_store(self, *, tenant_id: str, store_id: str) -> ObjectStoreBinding:
        binding = self._stores.get(store_id)
        if binding is None or binding.tenant_id != tenant_id:
            raise ManagedSecurityError("object store binding is not owned by the tenant")
        if not _allowed(binding.endpoint, self._allowed_endpoints):
            raise ManagedSecurityError("object store endpoint is outside the deployment allowlist")
        return binding
