from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

_LOCAL_REF = re.compile(r"^local:[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
_APPROVED_REF = re.compile(r"^approved:sha256:[a-f0-9]{64}$")


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReleaseRef(ClosedModel):
    version: str = Field(min_length=1, max_length=128)
    digest_ref: str

    @model_validator(mode="after")
    def immutable_digest(self):
        if not _APPROVED_REF.fullmatch(self.digest_ref):
            raise ValueError("release digest must be an approved sha256 reference")
        return self


class DSPyRelease(ReleaseRef):
    program_id: str = Field(min_length=1, max_length=128)
    approval_ref: str
    model_config_ref: str


class ReleaseSet(ClosedModel):
    application: ReleaseRef
    harness: ReleaseRef
    infrastructure: ReleaseRef
    database_schema: str = Field(min_length=1, max_length=128)
    policy: ReleaseRef
    dspy: DSPyRelease


class Placement(ClosedModel):
    adapter: Literal["aws-kubernetes"]
    account_binding_ref: str
    region: str = Field(pattern=r"^[a-z]{2}-[a-z]+-[1-9][0-9]*$")
    network_binding_ref: str
    state_binding_ref: str


class Isolation(ClosedModel):
    application: Literal["dedicated-runtime"]
    execution: Literal["dedicated-tenant-nodes"]
    database: Literal["dedicated-instance"]
    queue_cache: Literal["dedicated-instance"]


class Storage(ClosedModel):
    database_ref: str
    object_store_ref: str
    memory_ref: str
    queue_ref: str
    key_ref: str
    retention_policy_ref: str


class Credentials(ClosedModel):
    integration_secret_refs: list[str] = Field(max_length=64)
    workload_identity_ref: str


class Network(ClosedModel):
    ingress_policy_ref: str
    egress_policy_ref: str
    management_transport: Literal["outbound-mtls-https"]
    artifact_mirror_ref: str


class OperationsPolicy(ClosedModel):
    budget_policy_ref: str
    export_policy_ref: str
    backup_policy_ref: str
    recovery_targets_ref: str
    maintenance_policy_ref: str
    support_policy_ref: str
    approval_ref: str
    rollback_compatibility_ref: str


class DeploymentManifest(ClosedModel):
    contract_version: Literal["managed-soc/v1"]
    tenant_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,62}$")
    deployment_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,62}$")
    incarnation: uuid.UUID
    generation: int = Field(ge=1)
    expected_generation: int = Field(ge=0)
    mode: Literal["managed-dedicated", "byoc"]
    placement: Placement
    releases: ReleaseSet
    isolation: Isolation
    storage: Storage
    credentials: Credentials
    network: Network
    operations: OperationsPolicy

    @model_validator(mode="after")
    def validate_refs_and_generation(self):
        if self.generation != self.expected_generation + 1:
            raise ValueError("generation must advance exactly once")
        local_refs = [
            self.placement.account_binding_ref,
            self.placement.network_binding_ref,
            self.placement.state_binding_ref,
            self.releases.dspy.approval_ref,
            self.releases.dspy.model_config_ref,
            self.storage.database_ref,
            self.storage.object_store_ref,
            self.storage.memory_ref,
            self.storage.queue_ref,
            self.storage.key_ref,
            self.storage.retention_policy_ref,
            *self.credentials.integration_secret_refs,
            self.credentials.workload_identity_ref,
            self.network.ingress_policy_ref,
            self.network.egress_policy_ref,
            self.network.artifact_mirror_ref,
            self.operations.budget_policy_ref,
            self.operations.export_policy_ref,
            self.operations.backup_policy_ref,
            self.operations.recovery_targets_ref,
            self.operations.maintenance_policy_ref,
            self.operations.support_policy_ref,
            self.operations.approval_ref,
        ]
        if any(not _LOCAL_REF.fullmatch(value) for value in local_refs):
            raise ValueError("deployment references must be trusted local references")
        if not _APPROVED_REF.fullmatch(self.operations.rollback_compatibility_ref):
            raise ValueError("rollback compatibility must be an approved sha256 reference")
        if len(set(self.credentials.integration_secret_refs)) != len(
            self.credentials.integration_secret_refs
        ):
            raise ValueError("integration secret references must be unique")
        return self


class OperationRequest(ClosedModel):
    operation_kind: Literal["provision", "configure", "upgrade", "rollback"]
    manifest: DeploymentManifest


class OperationApproval(ClosedModel):
    manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    plan_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    expires_at: str


class OperationResponse(ClosedModel):
    operation_id: uuid.UUID
    deployment_id: str
    tenant_id: str
    operation_kind: str
    manifest_digest: str
    plan_hash: str | None = None
    expected_generation: int
    target_generation: int
    fencing_token: int
    status: str
    created_at: str
    updated_at: str


class ReconcileClaimRequest(ClosedModel):
    phase: Literal["plan", "apply"]
    runner_id: str = Field(min_length=1, max_length=200)


class PlanReadyRequest(ClosedModel):
    command_id: uuid.UUID
    fencing_token: int = Field(gt=0)
    manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    plan_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class OperationFailure(ClosedModel):
    command_id: uuid.UUID
    fencing_token: int = Field(gt=0)
    phase: Literal["plan", "apply"]
    error_code: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,127}$")
    error_detail: str = Field(min_length=1, max_length=4000)


class OperationReceipt(ClosedModel):
    operation_id: uuid.UUID
    command_id: uuid.UUID
    deployment_id: str
    tenant_id: str
    fencing_token: int = Field(gt=0)
    manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    plan_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    observed_generation: int = Field(gt=0)
    resource_inventory: dict[str, str]
    verification_summary: dict[str, str | int | bool]
    provider_update_id: str | None = None
    completed_at: str
    signature: str = Field(min_length=32)


class TenantContextResponse(ClosedModel):
    tenant_id: str
    organization_id: str
    display_name: str
    roles: list[Literal["tenant_admin", "analyst", "approver", "viewer"]]
    membership_version: int = Field(gt=0)
    deployment_id: str
    cell_id: str
    region: str


class RouteTicketResponse(ClosedModel):
    ticket: str
    expires_at: str
    tenant_id: str
    deployment_id: str
    cell_id: str


QuotaDimension = Literal[
    "api_requests",
    "agent_runs",
    "model_tokens",
    "tool_calls",
    "ingest_bytes",
    "stored_bytes",
]


class QuotaReservationRequest(ClosedModel):
    invocation_id: str = Field(min_length=1, max_length=200)
    request_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    dimension: QuotaDimension
    amount: int = Field(gt=0)


class QuotaCommitRequest(ClosedModel):
    request_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    actual_amount: int = Field(ge=0)


class QuotaReservationResponse(ClosedModel):
    reservation_id: uuid.UUID
    tenant_id: str
    deployment_id: str
    dimension: QuotaDimension
    reserved_amount: int
    committed_amount: int | None = None
    policy_version: int
    status: Literal["reserved", "committed", "released"]
    expires_at: str


class UsageWindowResponse(ClosedModel):
    tenant_id: str
    dimension: QuotaDimension
    window_started_at: str
    reserved_amount: int
    committed_amount: int
    hard_limit: int
    policy_version: int


class BYOCEnrollmentRequest(ClosedModel):
    tenant_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,62}$")
    deployment_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,62}$")
    account_id: str = Field(pattern=r"^[0-9]{12}$")
    connector_spiffe_id: str = Field(pattern=r"^spiffe://[A-Za-z0-9._:/-]{3,240}$")
    local_policy_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    expires_at: datetime
    idempotency_key: str = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def timezone_required(self):
        if self.expires_at.tzinfo is None:
            raise ValueError("enrollment expiry must include a timezone")
        return self


class BYOCEnrollmentResponse(ClosedModel):
    enrollment_id: uuid.UUID
    tenant_id: str
    deployment_id: str
    account_id: str
    connector_spiffe_id: str
    expires_at: str
    enrollment_token: str


class BYOCEnrollRequest(ClosedModel):
    enrollment_id: uuid.UUID
    enrollment_token: str = Field(min_length=32, max_length=256)
    account_id: str = Field(pattern=r"^[0-9]{12}$")
    local_policy_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    connector_public_key: str = Field(min_length=40, max_length=128)
    proof_signature: str = Field(min_length=40, max_length=256)
    certificate_signing_request: str = Field(min_length=128, max_length=16384)


class BYOCConnectorResponse(ClosedModel):
    tenant_id: str
    deployment_id: str
    account_id: str
    connector_spiffe_id: str
    local_policy_digest: str
    trust_version: int = Field(gt=0)
    revocation_epoch: int = Field(gt=0)
    management_enabled: bool
    last_health_sequence: int = Field(ge=0)
    last_health_at: str | None = None


class BYOCEnrollmentCompleteResponse(BYOCConnectorResponse):
    client_certificate: str
    ca_certificate: str
    certificate_expires_at: str
    certificate_serial: str = Field(pattern=r"^[a-f0-9]+$")


class BYOCCertificateRotationRequest(ClosedModel):
    certificate_signing_request: str = Field(min_length=128, max_length=16384)


class BYOCCertificateResponse(ClosedModel):
    client_certificate: str
    ca_certificate: str
    certificate_expires_at: str
    certificate_serial: str = Field(pattern=r"^[a-f0-9]+$")


class BYOCHealthPayload(ClosedModel):
    status: Literal["healthy", "degraded", "offline", "revoked"]
    observed_generation: int = Field(ge=0)
    release_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    backlog_count: int = Field(default=0, ge=0)
    dropped_count: int = Field(default=0, ge=0)
    storage_watermark_percent: int = Field(default=0, ge=0, le=100)
    dspy_evaluation: BYOCDSPyEvaluationReceipt | None = None


class BYOCDSPyEvaluationReceipt(ClosedModel):
    schema_version: Literal["autobot.dspy.evaluation-receipt/v1"]
    tenant_id: str
    deployment_id: str
    evaluation_id: uuid.UUID
    dataset_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    program_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    model_config_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    metric_contract_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    split_name: Literal["development", "holdout", "safety"]
    metrics: dict[str, float]
    passed: bool
    completed_at: datetime
    signature: str = Field(min_length=32, max_length=256)


BYOCHealthPayload.model_rebuild()


class BYOCHealthEvent(ClosedModel):
    incarnation: uuid.UUID
    sequence: int = Field(gt=0)
    event_kind: Literal["heartbeat", "release", "capacity", "gap", "revocation", "dspy_evaluation"]
    occurred_at: datetime
    revocation_epoch: int = Field(gt=0)
    payload: BYOCHealthPayload
    signature: str = Field(min_length=40, max_length=256)

    @model_validator(mode="after")
    def timezone_required(self):
        if self.occurred_at.tzinfo is None:
            raise ValueError("health occurrence time must include a timezone")
        if (self.event_kind == "dspy_evaluation") != (self.payload.dspy_evaluation is not None):
            raise ValueError("DSPy evaluation payload is bound only to its event kind")
        return self


class BYOCHealthReceipt(ClosedModel):
    deployment_id: str
    sequence: int = Field(gt=0)
    event_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    duplicate: bool


class IdentityProviderRequest(ClosedModel):
    provider_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,62}$")
    protocol: Literal["oidc", "saml"]
    issuer: str = Field(min_length=8, max_length=1024)
    audience: str = Field(min_length=1, max_length=512)
    oidc_jwks: dict | None = None
    oidc_algorithms: list[Literal["RS256", "ES256", "EdDSA"]] = Field(
        default_factory=lambda: ["RS256"], min_length=1, max_length=3
    )
    required_acr: list[str] = Field(default_factory=list, max_length=8)
    required_amr: list[str] = Field(default_factory=list, max_length=8)
    saml_sso_url: str | None = Field(default=None, max_length=2048)
    saml_entity_id: str | None = Field(default=None, max_length=1024)
    saml_acs_url: str | None = Field(default=None, max_length=2048)
    saml_signing_certificate: str | None = Field(default=None, max_length=16384)
    max_session_seconds: int = Field(default=600, ge=60, le=600)

    @model_validator(mode="after")
    def protocol_material(self):
        oidc = self.oidc_jwks is not None
        saml = all(
            (
                self.saml_sso_url,
                self.saml_entity_id,
                self.saml_acs_url,
                self.saml_signing_certificate,
            )
        )
        if self.protocol == "oidc" and (not oidc or saml):
            raise ValueError("OIDC providers require JWKS and cannot include SAML trust")
        if self.protocol == "saml" and (oidc or not saml):
            raise ValueError("SAML providers require complete SAML trust and no JWKS")
        return self


class SCIMTokenRequest(ClosedModel):
    expires_at: datetime


class SAMLLoginResponse(ClosedModel):
    provider_id: str
    request_id: str
    relay_state: str
    sso_url: str
    saml_request: str
    expires_at: datetime


class SAMLAssertionRequest(ClosedModel):
    saml_response: str = Field(min_length=128, max_length=262144)
    relay_state: str = Field(min_length=32, max_length=512)


class FederatedSessionResponse(ClosedModel):
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_at: datetime


class OperatorAccessRequest(ClosedModel):
    tenant_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,62}$")
    deployment_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,127}$")
    access_kind: Literal["support", "break_glass"] = "support"
    actions: list[str] = Field(min_length=1, max_length=16)
    resources: list[str] = Field(min_length=1, max_length=32)
    justification: str = Field(min_length=10, max_length=2000)
    ticket_ref: str = Field(min_length=1, max_length=200)
    incident_ref: str | None = Field(default=None, min_length=1, max_length=200)
    duration_seconds: int = Field(ge=60, le=900)

    @model_validator(mode="after")
    def exact_scope(self):
        values = [*self.actions, *self.resources]
        if any(not value or "*" in value for value in values):
            raise ValueError("operator access scopes must be explicit and cannot use wildcards")
        if len(set(self.actions)) != len(self.actions) or len(set(self.resources)) != len(
            self.resources
        ):
            raise ValueError("operator access scopes cannot contain duplicates")
        if self.access_kind == "break_glass":
            if not self.incident_ref or self.duration_seconds > 300:
                raise ValueError(
                    "break-glass access requires an incident and expires within five minutes"
                )
        elif self.incident_ref is not None:
            raise ValueError("incident_ref is reserved for break-glass access")
        return self


class OperatorAccessApproval(ClosedModel):
    request_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class OperatorAccessAuthorization(ClosedModel):
    action: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def exact_target(self):
        if "*" in self.action or "*" in self.resource:
            raise ValueError("authorization targets cannot use wildcards")
        return self


class OperatorAccessSessionResponse(ClosedModel):
    session_id: uuid.UUID
    request_id: uuid.UUID
    tenant_id: str
    deployment_id: str
    expires_at: datetime
    session_token: str


class OperatorAccessDecision(ClosedModel):
    allowed: bool
    reason_code: str
    tenant_id: str
    deployment_id: str
    action: str
    resource: str
    session_id: uuid.UUID
    expires_at: datetime
