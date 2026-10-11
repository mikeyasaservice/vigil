import pytest

from core.agents.managed_bindings import ManagedBindingRegistry, ObjectStoreBinding, SecretBinding
from core.agents.managed_execution import ManagedSecurityError


def test_bindings_are_tenant_owned_and_endpoint_bounded() -> None:
    registry = ManagedBindingRegistry(
        secrets={"secret/a": SecretBinding("tenant-a", "jira-a", "secret/a", "http://localstack-a:4566")},
        stores={"objects/a": ObjectStoreBinding("tenant-a", "objects/a", "findings-a", "runs/", "http://localstack-a:4566")},
        allowed_endpoints=("http://localstack-a:4566",),
    )
    assert registry.secret(tenant_id="tenant-a", integration_id="jira-a", secret_ref="secret/a").secret_ref == "secret/a"
    assert registry.object_store(tenant_id="tenant-a", store_id="objects/a").bucket == "findings-a"
    with pytest.raises(ManagedSecurityError):
        registry.secret(tenant_id="tenant-b", integration_id="jira-a", secret_ref="secret/a")
    with pytest.raises(ManagedSecurityError):
        ManagedBindingRegistry(
            secrets={"secret/a": SecretBinding("tenant-a", "jira-a", "secret/a", "https://attacker.invalid")},
            stores={},
            allowed_endpoints=("http://localstack-a:4566",),
        ).secret(tenant_id="tenant-a", integration_id="jira-a", secret_ref="secret/a")
