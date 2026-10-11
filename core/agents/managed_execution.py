"""Managed execution identity, admission, and capability authorization.

This module is deliberately independent of the LLM and of the queue client.  It
is the small trusted core used by both the API admission path and the worker
gateway.  The in-memory authority is useful for deterministic tests; production
adapters can persist the same records without changing the signed wire format.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Mapping, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


SCHEMA_VERSION = 2
MAX_GRANT_TTL = timedelta(seconds=60)


class ManagedSecurityError(ValueError):
    """A request failed a managed security invariant."""


class AuthorizationUnavailable(ManagedSecurityError):
    """Required local security state was unavailable; callers must fail closed."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    deployment_id: str
    subject_id: str
    issuer: str
    roles: tuple[str, ...]
    membership_version: int
    policy_version: str
    request_id: str

    def __post_init__(self) -> None:
        if not all((self.tenant_id, self.deployment_id, self.subject_id, self.issuer, self.request_id)):
            raise ManagedSecurityError("tenant context fields are required")
        if self.membership_version < 1:
            raise ManagedSecurityError("membership version must be positive")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "deployment_id": self.deployment_id,
            "subject_id": self.subject_id,
            "issuer": self.issuer,
            "roles": list(self.roles),
            "membership_version": self.membership_version,
            "policy_version": self.policy_version,
            "request_id": self.request_id,
        }


@dataclass(frozen=True)
class Admission:
    admission_id: str
    context: TenantContext
    workflow_id: str
    workflow_digest: str
    program_id: str
    program_digest: str
    request_digest: str
    issued_at: datetime
    expires_at: datetime
    revocation_epoch: int
    status: str = "active"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "admission_id": self.admission_id,
            "context": self.context.as_dict(),
            "workflow_id": self.workflow_id,
            "workflow_digest": self.workflow_digest,
            "program_id": self.program_id,
            "program_digest": self.program_digest,
            "request_digest": self.request_digest,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "revocation_epoch": self.revocation_epoch,
        }


@dataclass(frozen=True)
class QueueEnvelope:
    admission: Admission
    execution_id: str
    reason: str
    references: Mapping[str, str]
    signature: str

    @property
    def signed_payload(self) -> Dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "admission": self.admission.as_dict(),
            "execution_id": self.execution_id,
            "reason": self.reason,
            "references": dict(self.references),
        }

    def as_dict(self) -> Dict[str, Any]:
        return {**self.signed_payload, "signature": self.signature}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "QueueEnvelope":
        try:
            raw = value["admission"]
            context_raw = raw["context"]
            context = TenantContext(
                tenant_id=str(context_raw["tenant_id"]),
                deployment_id=str(context_raw["deployment_id"]),
                subject_id=str(context_raw["subject_id"]),
                issuer=str(context_raw["issuer"]),
                roles=tuple(str(role) for role in context_raw["roles"]),
                membership_version=int(context_raw["membership_version"]),
                policy_version=str(context_raw["policy_version"]),
                request_id=str(context_raw["request_id"]),
            )
            admission = Admission(
                admission_id=str(raw["admission_id"]),
                context=context,
                workflow_id=str(raw["workflow_id"]),
                workflow_digest=str(raw["workflow_digest"]),
                program_id=str(raw["program_id"]),
                program_digest=str(raw["program_digest"]),
                request_digest=str(raw["request_digest"]),
                issued_at=datetime.fromisoformat(str(raw["issued_at"])),
                expires_at=datetime.fromisoformat(str(raw["expires_at"])),
                revocation_epoch=int(raw["revocation_epoch"]),
            )
            return cls(
                admission=admission,
                execution_id=str(value["execution_id"]),
                reason=str(value["reason"]),
                references={str(k): str(v) for k, v in value["references"].items()},
                signature=str(value["signature"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ManagedSecurityError("malformed managed queue envelope") from exc


@dataclass(frozen=True)
class ExecutionIdentity:
    execution_id: str
    tenant_id: str
    deployment_id: str
    worker_key_id: str
    workflow_id: str
    workflow_digest: str
    program_id: str
    program_digest: str
    capabilities: tuple[str, ...]
    policy_version: str
    revocation_epoch: int
    issued_at: datetime
    expires_at: datetime
    jti: str


@dataclass(frozen=True)
class ToolGrant:
    grant_id: str
    execution_id: str
    tenant_id: str
    deployment_id: str
    action: str
    resource: str
    argument_digest: str
    approval_digest: Optional[str]
    policy_version: str
    revocation_epoch: int
    issued_at: datetime
    expires_at: datetime
    workload_key_id: str
    claim_jti: str


@dataclass(frozen=True)
class Invocation:
    invocation_id: str
    execution_id: str
    tenant_id: str
    action: str
    resource: str
    arguments: Mapping[str, Any]
    grant: ToolGrant
    budget_units: int = 1

    def __post_init__(self) -> None:
        if self.budget_units <= 0:
            raise ManagedSecurityError("invocation budget must be positive")

    @property
    def argument_digest(self) -> str:
        return _digest(self.arguments)


class Ed25519Signer:
    """Small signing adapter with JSON-safe encoded signatures."""

    def __init__(self, private_key: Optional[Ed25519PrivateKey] = None) -> None:
        self._private = private_key or Ed25519PrivateKey.generate()

    @property
    def key_id(self) -> str:
        public = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return hashlib.sha256(public).hexdigest()[:24]

    @property
    def public_key_b64(self) -> str:
        public = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return base64.urlsafe_b64encode(public).decode().rstrip("=")

    def sign(self, payload: Mapping[str, Any]) -> str:
        return base64.urlsafe_b64encode(self._private.sign(_canonical(payload))).decode()

    def verifier(self) -> "Ed25519Verifier":
        return Ed25519Verifier(self._private.public_key(), self.key_id)


class Ed25519Verifier:
    def __init__(self, public_key: Ed25519PublicKey, key_id: str) -> None:
        self.public_key = public_key
        self.key_id = key_id

    def verify(self, payload: Mapping[str, Any], signature: str) -> None:
        try:
            padded = signature + "=" * (-len(signature) % 4)
            raw = base64.urlsafe_b64decode(padded.encode())
            self.public_key.verify(raw, _canonical(payload))
        except Exception as exc:  # cryptography intentionally exposes several error types
            raise ManagedSecurityError("invalid managed envelope signature") from exc


@dataclass
class ManagedAuthority:
    """Fail-closed authority used by the managed API and gateway adapters."""

    signer: Ed25519Signer = field(default_factory=Ed25519Signer)
    verifier: Optional[Ed25519Verifier] = None
    admissions: Dict[str, Admission] = field(default_factory=dict)
    executions: Dict[str, ExecutionIdentity] = field(default_factory=dict)
    grants: Dict[str, ToolGrant] = field(default_factory=dict)
    revoked_epochs: Dict[str, int] = field(default_factory=dict)
    cancelled_executions: set[str] = field(default_factory=set)
    approvals: Dict[str, tuple[str, str, str, str]] = field(default_factory=dict)
    invocation_results: Dict[str, tuple[str, Any]] = field(default_factory=dict)
    invocation_reservations: Dict[str, str] = field(default_factory=dict)
    budgets: Dict[str, int] = field(default_factory=dict)

    def admit(
        self,
        context: TenantContext,
        *,
        admission_id: str,
        workflow_id: str,
        workflow_digest: str,
        program_id: str,
        program_digest: str,
        request: Mapping[str, Any],
        references: Optional[Mapping[str, str]] = None,
        ttl: timedelta = timedelta(minutes=5),
    ) -> QueueEnvelope:
        if ttl <= timedelta(0) or ttl > timedelta(hours=1):
            raise ManagedSecurityError("admission lifetime is outside the allowed range")
        if context.tenant_id in self.revoked_epochs:
            epoch = self.revoked_epochs[context.tenant_id]
        else:
            epoch = 0
        now = _now()
        admission = Admission(
            admission_id=admission_id,
            context=context,
            workflow_id=workflow_id,
            workflow_digest=workflow_digest,
            program_id=program_id,
            program_digest=program_digest,
            request_digest=_digest(request),
            issued_at=now,
            expires_at=now + ttl,
            revocation_epoch=epoch,
        )
        self.admissions[admission_id] = admission
        execution_id = str(uuid.uuid4())
        envelope = QueueEnvelope(
            admission=admission,
            execution_id=execution_id,
            reason="start",
            references={
                "request_digest": admission.request_digest,
                "run_id": str((references or {}).get("run_id", admission_id)),
                "run_kind": str((references or {}).get("run_kind", "investigate")),
                **({str(k): str(v) for k, v in (references or {}).items()}),
            },
            signature="",
        )
        return QueueEnvelope(
            admission=admission,
            execution_id=execution_id,
            reason=envelope.reason,
            references=envelope.references,
            signature=self.signer.sign(envelope.signed_payload),
        )

    def verify_envelope(self, envelope: QueueEnvelope, *, deployment_id: str) -> Admission:
        (self.verifier or self.signer.verifier()).verify(envelope.signed_payload, envelope.signature)
        admission = self.admissions.get(envelope.admission.admission_id)
        # The signed admission is intentionally self-contained so a queue
        # consumer in another process can verify it without sharing an API
        # process's memory. A durable adapter may additionally compare the
        # record by id; the signature remains the source of authenticity.
        if admission is not None and admission != envelope.admission:
            raise ManagedSecurityError("admission is unknown or has been altered")
        admission = envelope.admission
        if not envelope.execution_id or len(envelope.execution_id) < 16:
            raise ManagedSecurityError("managed execution id is invalid")
        if envelope.references.get("request_digest") != admission.request_digest:
            raise ManagedSecurityError("queue request binding is invalid")
        if not envelope.references.get("run_id"):
            raise ManagedSecurityError("queue run binding is missing")
        if not envelope.references.get("run_kind"):
            raise ManagedSecurityError("queue run kind binding is missing")
        if admission.context.deployment_id != deployment_id:
            raise ManagedSecurityError("queue target is not the admission deployment")
        if admission.expires_at <= _now():
            raise ManagedSecurityError("admission has expired")
        if admission.revocation_epoch < self.revoked_epochs.get(admission.context.tenant_id, 0):
            raise ManagedSecurityError("admission was revoked")
        return admission

    def reissue(self, envelope: QueueEnvelope, *, reason: str) -> QueueEnvelope:
        """Issue a fresh queue signature without changing the admitted work."""
        if reason not in {"start", "resume"}:
            raise ManagedSecurityError("unsupported managed queue reason")
        self.verify_envelope(envelope, deployment_id=envelope.admission.context.deployment_id)
        renewed = QueueEnvelope(
            admission=envelope.admission,
            execution_id=envelope.execution_id,
            reason=reason,
            references=envelope.references,
            signature="",
        )
        return QueueEnvelope(
            admission=renewed.admission,
            execution_id=renewed.execution_id,
            reason=renewed.reason,
            references=renewed.references,
            signature=self.signer.sign(renewed.signed_payload),
        )

    def claim(
        self,
        envelope: QueueEnvelope,
        *,
        worker_key_id: str,
        capabilities: Iterable[str],
        deployment_id: Optional[str] = None,
    ) -> ExecutionIdentity:
        expected_deployment = deployment_id or envelope.admission.context.deployment_id
        admission = self.verify_envelope(envelope, deployment_id=expected_deployment)
        existing = self.executions.get(envelope.execution_id)
        if existing is not None:
            if existing.worker_key_id != worker_key_id:
                raise ManagedSecurityError("execution is fenced to another worker")
            # A retry/takeover gets a fresh claim token. Grants issued under the
            # previous token are rejected by authorize even when the worker key is
            # unchanged.
        now = _now()
        identity = ExecutionIdentity(
            execution_id=envelope.execution_id,
            tenant_id=admission.context.tenant_id,
            deployment_id=admission.context.deployment_id,
            worker_key_id=worker_key_id,
            workflow_id=admission.workflow_id,
            workflow_digest=admission.workflow_digest,
            program_id=admission.program_id,
            program_digest=admission.program_digest,
            capabilities=tuple(sorted(set(capabilities))),
            policy_version=admission.context.policy_version,
            revocation_epoch=admission.revocation_epoch,
            issued_at=now,
            expires_at=min(admission.expires_at, now + timedelta(minutes=15)),
            jti=secrets.token_hex(16),
        )
        self.executions[identity.execution_id] = identity
        self.budgets.setdefault(identity.execution_id, 100)
        return identity

    @staticmethod
    def _execution_attestation_payload(identity: ExecutionIdentity) -> dict[str, Any]:
        return {
            "aud": "vigil-managed-gateway",
            "execution_id": identity.execution_id,
            "tenant_id": identity.tenant_id,
            "deployment_id": identity.deployment_id,
            "worker_key_id": identity.worker_key_id,
            "workflow_id": identity.workflow_id,
            "workflow_digest": identity.workflow_digest,
            "program_id": identity.program_id,
            "program_digest": identity.program_digest,
            "policy_version": identity.policy_version,
            "revocation_epoch": identity.revocation_epoch,
            "expires_at": identity.expires_at.isoformat(),
            "jti": identity.jti,
        }

    def sign_execution_attestation(self, identity: ExecutionIdentity) -> str:
        return self.signer.sign(self._execution_attestation_payload(identity))

    def verify_execution_attestation(self, identity: ExecutionIdentity, attestation: str) -> None:
        (self.verifier or self.signer.verifier()).verify(
            self._execution_attestation_payload(identity), attestation
        )

    def revoke(self, tenant_id: str) -> int:
        epoch = self.revoked_epochs.get(tenant_id, 0) + 1
        self.revoked_epochs[tenant_id] = epoch
        return epoch

    def cancel_execution(self, execution_id: str) -> None:
        self.cancelled_executions.add(execution_id)

    def approve_execution(
        self,
        execution_id: str,
        *,
        approval_digest: str,
        action: str,
        resource: str,
        argument_digest: str,
    ) -> None:
        if not approval_digest or not action or not resource or not argument_digest:
            raise ManagedSecurityError("approval binding is incomplete")
        self.approvals[approval_digest] = (execution_id, action, resource, argument_digest)

    def grant(
        self,
        identity: ExecutionIdentity,
        *,
        grant_id: str,
        action: str,
        resource: str,
        arguments: Mapping[str, Any],
        workload_key_id: str,
        approval_digest: Optional[str] = None,
        ttl: timedelta = MAX_GRANT_TTL,
    ) -> ToolGrant:
        self._check_execution(identity)
        if action not in identity.capabilities:
            raise ManagedSecurityError("action is not granted to this execution")
        if workload_key_id != identity.worker_key_id:
            raise ManagedSecurityError("grant workload binding does not match execution")
        if ttl <= timedelta(0) or ttl > MAX_GRANT_TTL:
            raise ManagedSecurityError("tool grant lifetime exceeds the 60 second maximum")
        now = _now()
        argument_digest = _digest(arguments)
        if approval_digest is not None:
            approval = self.approvals.get(approval_digest)
            if approval != (identity.execution_id, action, resource, argument_digest):
                raise ManagedSecurityError("approval binding is invalid")
        grant = ToolGrant(
            grant_id=grant_id,
            execution_id=identity.execution_id,
            tenant_id=identity.tenant_id,
            deployment_id=identity.deployment_id,
            action=action,
            resource=resource,
            argument_digest=argument_digest,
            approval_digest=approval_digest,
            policy_version=identity.policy_version,
            revocation_epoch=identity.revocation_epoch,
            issued_at=now,
            expires_at=min(identity.expires_at, now + ttl),
            workload_key_id=workload_key_id,
            claim_jti=identity.jti,
        )
        self.grants[grant_id] = grant
        return grant

    def authorize(self, invocation: Invocation) -> None:
        identity = self.executions.get(invocation.execution_id)
        if identity is None:
            raise ManagedSecurityError("execution is unknown")
        self._check_execution(identity)
        grant = self.grants.get(invocation.grant.grant_id)
        if grant is None or grant != invocation.grant:
            raise ManagedSecurityError("grant is unknown or has been altered")
        if grant.expires_at <= _now():
            raise ManagedSecurityError("grant has expired")
        if grant.execution_id != identity.execution_id or invocation.execution_id != grant.execution_id:
            raise ManagedSecurityError("grant execution does not match invocation")
        if grant.tenant_id != identity.tenant_id or grant.deployment_id != identity.deployment_id:
            raise ManagedSecurityError("grant tenant does not match execution")
        if grant.workload_key_id != identity.worker_key_id:
            raise ManagedSecurityError("grant workload does not match execution")
        if grant.claim_jti != identity.jti:
            raise ManagedSecurityError("grant belongs to a fenced claim")
        if grant.policy_version != identity.policy_version or grant.revocation_epoch != identity.revocation_epoch:
            raise ManagedSecurityError("grant policy is stale")
        if invocation.tenant_id != identity.tenant_id or grant.action != invocation.action:
            raise ManagedSecurityError("invocation identity does not match grant")
        if grant.resource != invocation.resource or grant.argument_digest != invocation.argument_digest:
            raise ManagedSecurityError("invocation arguments are outside the grant")
        if grant.approval_digest is not None:
            approval = self.approvals.get(grant.approval_digest)
            if approval != (identity.execution_id, invocation.action, invocation.resource, invocation.argument_digest):
                raise ManagedSecurityError("approval binding is invalid")
        digest = _digest({"action": invocation.action, "resource": invocation.resource, "arguments": dict(invocation.arguments)})
        prior = self.invocation_reservations.get(invocation.invocation_id)
        if prior is not None:
            if prior != digest:
                raise ManagedSecurityError("invocation id was reused with different content")
            return
        remaining = self.budgets.get(identity.execution_id)
        if remaining is None:
            raise AuthorizationUnavailable("execution budget state is unavailable")
        if remaining < invocation.budget_units:
            raise ManagedSecurityError("execution budget exhausted")
        self.invocation_reservations[invocation.invocation_id] = digest
        self.budgets[identity.execution_id] = remaining - invocation.budget_units

    def record_invocation(self, invocation: Invocation, result: Any) -> None:
        digest = _digest({"action": invocation.action, "resource": invocation.resource, "arguments": dict(invocation.arguments)})
        prior = self.invocation_results.get(invocation.invocation_id)
        if prior is not None and prior[0] != digest:
            raise ManagedSecurityError("invocation id was reused with different content")
        self.invocation_results[invocation.invocation_id] = (digest, result)

    def _check_execution(self, identity: ExecutionIdentity) -> None:
        if identity.execution_id in self.cancelled_executions:
            raise ManagedSecurityError("execution was cancelled")
        if identity.expires_at <= _now():
            raise ManagedSecurityError("execution identity has expired")
        if identity.revocation_epoch < self.revoked_epochs.get(identity.tenant_id, 0):
            raise ManagedSecurityError("execution identity was revoked")
