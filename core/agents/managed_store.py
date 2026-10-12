"""Durable managed-run repository.

The managed API uses this repository for admission, lifecycle state, and the
outbox record. Worker SQL credentials are denied these tables by migration.
"""

from __future__ import annotations

import base64
import json
import uuid
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import text

from core.agents.managed_execution import (
    Admission,
    ExecutionIdentity,
    ManagedSecurityError,
    QueueEnvelope,
    Ed25519Verifier,
)
from core.storage.unit_of_work import unit_of_work


def program_registry_payload(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "tenant_id": str(row["tenant_id"]),
        "program_id": str(row["program_id"]),
        "program_digest": str(row["program_digest"]),
        "model_config_digest": str(row["model_config_digest"]),
        "dependency_digest": str(row["dependency_digest"]),
        "status": str(row["status"]),
    }


def verify_program_registry_record(row: dict[str, Any]) -> bool:
    try:
        raw = str(row["authority_public_key"])
        padded = raw + "=" * (-len(raw) % 4)
        verifier = Ed25519Verifier(
            Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(padded)),
            "managed-program-registry",
        )
        verifier.verify(program_registry_payload(row), str(row["artifact_signature"]))
        return True
    except (KeyError, TypeError, ValueError, ManagedSecurityError):
        return False


class ManagedRunStore:
    def resolve_membership(
        self, subject_id: str, issuer: str, tenant_hint: str | None
    ) -> dict[str, Any] | None:
        from core.storage.connection import get_db_session

        with get_db_session() as session:
            rows = session.execute(text("""
                SELECT m.tenant_id, d.deployment_id, d.incarnation, m.roles,
                       m.membership_version, d.policy_version, m.issuer
                FROM managed_memberships m
                JOIN managed_deployments d ON d.tenant_id = m.tenant_id
                WHERE m.subject_id = :subject_id AND m.issuer = :issuer
                  AND m.status = 'active' AND d.status = 'active'
                  AND (:tenant_hint IS NULL OR m.tenant_id = :tenant_hint)
            """), {"subject_id": subject_id, "issuer": issuer,
                    "tenant_hint": tenant_hint}).mappings().all()
        if len(rows) != 1:
            return None
        return dict(rows[0])

    def program_active(self, tenant_id: str, program_id: str, program_digest: str) -> bool:
        from core.storage.connection import get_db_session

        with get_db_session() as session:
            row = session.execute(text("""
                SELECT p.tenant_id, p.program_id, p.program_digest,
                       p.artifact_signature, p.model_config_digest,
                       p.dependency_digest, p.status, d.authority_public_key
                FROM managed_program_registry p
                JOIN managed_deployments d ON d.tenant_id = p.tenant_id
                WHERE p.tenant_id = :tenant_id AND p.program_id = :program_id
                  AND p.program_digest = :program_digest AND p.status = 'active'
                  AND d.status = 'active'
            """), {"tenant_id": tenant_id, "program_id": program_id,
                    "program_digest": program_digest}).mappings().one_or_none()
        return row is not None and verify_program_registry_record(dict(row))

    def integration_binding(self, tenant_id: str, tool_name: str) -> str | None:
        from core.storage.connection import get_db_session

        with get_db_session() as session:
            row = session.execute(text("""
                SELECT binding_id FROM managed_integration_bindings
                WHERE tenant_id = :tenant_id AND tool_name = :tool_name
                  AND status = 'active'
            """), {"tenant_id": tenant_id, "tool_name": tool_name}).one_or_none()
        return None if row is None else str(row.binding_id)

    def reserve_invocation(
        self,
        *,
        invocation_id: str,
        execution_id: str,
        tenant_id: str,
        action: str,
        resource: str,
        argument_digest: str,
        reserved_units: int,
    ) -> dict[str, Any] | None:
        """Reserve once and refuse an unresolved retry instead of replaying it."""
        if reserved_units <= 0:
            raise ManagedSecurityError("invocation budget must be positive")
        try:
            uuid.UUID(invocation_id)
        except ValueError as exc:
            raise ManagedSecurityError("invocation id is not a UUID") from exc
        with unit_of_work() as session:
            inserted = session.execute(text("""
                INSERT INTO managed_invocation_reservations
                (invocation_id, execution_id, tenant_id, action, resource,
                 argument_digest, reserved_units)
                VALUES (CAST(:invocation_id AS uuid), CAST(:execution_id AS uuid),
                 :tenant_id, :action, :resource, :argument_digest, :reserved_units)
                ON CONFLICT (invocation_id) DO NOTHING
                RETURNING invocation_id
            """), {
                "invocation_id": invocation_id,
                "execution_id": execution_id,
                "tenant_id": tenant_id,
                "action": action,
                "resource": resource,
                "argument_digest": argument_digest,
                "reserved_units": reserved_units,
            }).one_or_none()
            if inserted is not None:
                charged = session.execute(text("""
                    UPDATE managed_execution_budgets
                    SET remaining_units = remaining_units - :reserved_units,
                        updated_at = now()
                    WHERE execution_id = CAST(:execution_id AS uuid)
                      AND remaining_units >= :reserved_units
                """), {
                    "execution_id": execution_id,
                    "reserved_units": reserved_units,
                })
                if charged.rowcount != 1:
                    raise ManagedSecurityError("execution budget is unavailable or exhausted")
                session.execute(text("""
                    INSERT INTO managed_authorization_audit
                    (execution_id, tenant_id, action, resource, decision,
                     reason_code, argument_digest)
                    VALUES (CAST(:execution_id AS uuid), :tenant_id, :action,
                     :resource, 'allow', 'reserved', :argument_digest)
                """), {
                    "execution_id": execution_id,
                    "tenant_id": tenant_id,
                    "action": action,
                    "resource": resource,
                    "argument_digest": argument_digest,
                })
                return None
            existing = session.execute(text("""
                SELECT execution_id, tenant_id, action, resource, argument_digest,
                       reserved_units, outcome
                FROM managed_invocation_reservations
                WHERE invocation_id = CAST(:invocation_id AS uuid)
            """), {"invocation_id": invocation_id}).mappings().one()
            if any(existing[key] != value for key, value in {
                "execution_id": uuid.UUID(execution_id),
                "tenant_id": tenant_id,
                "action": action,
                "resource": resource,
                "argument_digest": argument_digest,
                "reserved_units": reserved_units,
            }.items()):
                raise ManagedSecurityError("invocation id was reused with different content")
            if existing["outcome"] is None:
                raise ManagedSecurityError("invocation outcome is unresolved")
            return existing["outcome"]

    def complete_invocation(self, invocation_id: str, execution_id: str, outcome: dict[str, Any]) -> None:
        with unit_of_work() as session:
            session.execute(text("""
                UPDATE managed_invocation_reservations
                SET outcome = CAST(:outcome AS jsonb)
                WHERE invocation_id = CAST(:invocation_id AS uuid)
                  AND execution_id = CAST(:execution_id AS uuid)
                  AND outcome IS NULL
            """), {
                "invocation_id": invocation_id,
                "execution_id": execution_id,
                "outcome": json.dumps(outcome, sort_keys=True),
            })

    def record_authorization_denial(
        self,
        *,
        execution_id: str,
        tenant_id: str,
        action: str,
        resource: str,
        argument_digest: str,
        reason_code: str,
    ) -> bool:
        """Record a denial only for a durable execution/tenant ownership pair."""
        if not all((action, resource, argument_digest, reason_code)):
            raise ManagedSecurityError("authorization denial audit is incomplete")
        with unit_of_work() as session:
            inserted = session.execute(text("""
                INSERT INTO managed_authorization_audit
                (execution_id, tenant_id, action, resource, decision,
                 reason_code, argument_digest)
                SELECT a.execution_id, a.tenant_id, :action, :resource,
                       'deny', :reason_code, :argument_digest
                FROM managed_admissions a
                WHERE a.execution_id = CAST(:execution_id AS uuid)
                  AND a.tenant_id = :tenant_id
                RETURNING audit_id
            """), {
                "execution_id": execution_id,
                "tenant_id": tenant_id,
                "action": action,
                "resource": resource,
                "argument_digest": argument_digest,
                "reason_code": reason_code,
            }).one_or_none()
        return inserted is not None

    def record_claim(
        self,
        envelope: QueueEnvelope,
        identity: ExecutionIdentity,
    ) -> None:
        """Atomically validate durable admission and fence the prior claimant."""
        admission = envelope.admission
        context = admission.context
        references = envelope.references
        with unit_of_work() as session:
            durable = session.execute(text("""
                SELECT 1
                FROM managed_admissions a
                JOIN managed_runs r ON r.execution_id = a.execution_id
                JOIN managed_deployments d ON d.deployment_id = a.deployment_id
                JOIN managed_memberships m
                  ON m.tenant_id = a.tenant_id AND m.subject_id = a.subject_id
                 AND m.issuer = a.issuer
                JOIN managed_program_registry p
                  ON p.tenant_id = a.tenant_id AND p.program_id = a.program_id
                 AND p.program_digest = a.program_digest
                WHERE a.admission_id = CAST(:admission_id AS uuid)
                  AND a.execution_id = CAST(:execution_id AS uuid)
                  AND a.tenant_id = :tenant_id
                  AND a.deployment_id = :deployment_id
                  AND a.subject_id = :subject_id
                  AND a.workflow_id = :workflow_id
                  AND a.workflow_digest = :workflow_digest
                  AND a.program_id = :program_id
                  AND a.program_digest = :program_digest
                  AND a.request_digest = :request_digest
                  AND a.revocation_epoch = :revocation_epoch
                  AND a.membership_version = :membership_version
                  AND a.policy_version = :policy_version
                  AND a.status = 'active' AND a.expires_at > now()
                  AND r.run_id = CAST(:run_id AS uuid)
                  AND r.run_kind = :run_kind
                  AND r.workflow_id = :workflow_id
                  AND r.status IN ('queued', 'running')
                  AND d.tenant_id = a.tenant_id AND d.status = 'active'
                  AND d.incarnation = CAST(:deployment_incarnation AS uuid)
                  AND d.revocation_epoch = a.revocation_epoch
                  AND m.status = 'active'
                  AND m.membership_version = a.membership_version
                  AND p.status = 'active'
                -- The run row is the lifecycle serialization point. Cancellation
                -- updates it first, so locking it here orders claim vs. revoke
                -- without granting the security role admission write authority.
                FOR UPDATE OF r
            """), {
                "admission_id": admission.admission_id,
                "execution_id": identity.execution_id,
                "tenant_id": identity.tenant_id,
                "deployment_id": identity.deployment_id,
                "deployment_incarnation": identity.deployment_incarnation,
                "subject_id": context.subject_id,
                "workflow_id": identity.workflow_id,
                "workflow_digest": identity.workflow_digest,
                "program_id": identity.program_id,
                "program_digest": identity.program_digest,
                "request_digest": admission.request_digest,
                "revocation_epoch": identity.revocation_epoch,
                "membership_version": context.membership_version,
                "policy_version": identity.policy_version,
                "run_id": references.get("run_id", ""),
                "run_kind": references.get("run_kind", ""),
            }).one_or_none()
            if durable is None:
                raise ManagedSecurityError("durable managed admission is not claimable")
            session.execute(text("""
                UPDATE managed_execution_claims SET status = 'fenced'
                WHERE execution_id = CAST(:execution_id AS uuid) AND status = 'active'
            """), {"execution_id": identity.execution_id})
            session.execute(text("""
                INSERT INTO managed_execution_claims
                (execution_id, worker_key_id, workload_spiffe_id, claim_token,
                 claim_version, claim_until, status, capabilities,
                 deployment_incarnation)
                VALUES (CAST(:execution_id AS uuid), :workload_spiffe_id,
                        :workload_spiffe_id, :claim_token,
                        (SELECT COALESCE(MAX(claim_version), 0) + 1
                         FROM managed_execution_claims
                         WHERE execution_id = CAST(:execution_id AS uuid)),
                        :claim_until, 'active', CAST(:capabilities AS jsonb),
                        CAST(:deployment_incarnation AS uuid))
                ON CONFLICT (execution_id) DO UPDATE SET
                  worker_key_id = EXCLUDED.worker_key_id,
                  workload_spiffe_id = EXCLUDED.workload_spiffe_id,
                  claim_token = EXCLUDED.claim_token,
                  claim_version = managed_execution_claims.claim_version + 1,
                  claim_until = EXCLUDED.claim_until,
                  status = 'active',
                  capabilities = EXCLUDED.capabilities,
                  deployment_incarnation = EXCLUDED.deployment_incarnation
            """), {
                "execution_id": identity.execution_id,
                "workload_spiffe_id": identity.worker_key_id,
                "claim_token": identity.jti,
                "claim_until": identity.expires_at,
                "capabilities": json.dumps(sorted(set(identity.capabilities))),
                "deployment_incarnation": identity.deployment_incarnation,
            })
            session.execute(text("""
                UPDATE managed_runs SET status = 'running', updated_at = now()
                WHERE execution_id = CAST(:execution_id AS uuid)
                  AND status <> 'cancelled'
            """), {"execution_id": identity.execution_id})

    def authorization_context(
        self, execution_id: str, workload_spiffe_id: str, claim_token: str
    ) -> dict[str, Any] | None:
        """Load the complete current authority for one dispatch.

        This deliberately joins revocable state instead of trusting a prior
        process's cache. A gateway restart and a cancellation therefore reach
        the same answer.
        """
        from core.storage.connection import get_db_session

        with get_db_session() as session:
            row = session.execute(text("""
                SELECT a.execution_id, a.tenant_id, a.deployment_id,
                       a.workflow_id, a.workflow_digest, a.program_id,
                       a.program_digest, COALESCE(a.policy_version, d.policy_version) AS policy_version,
                       a.revocation_epoch, c.claimed_at AS issued_at,
                       c.claim_until AS expires_at,
                       c.claim_token AS jti, c.claim_version,
                       c.workload_spiffe_id, c.capabilities,
                       c.deployment_incarnation
                FROM managed_execution_claims c
                JOIN managed_admissions a ON a.execution_id = c.execution_id
                JOIN managed_runs r ON r.execution_id = a.execution_id
                JOIN managed_deployments d ON d.deployment_id = a.deployment_id
                JOIN managed_memberships m
                  ON m.tenant_id = a.tenant_id AND m.subject_id = a.subject_id
                 AND (a.issuer IS NULL OR m.issuer = a.issuer)
                JOIN managed_program_registry p
                  ON p.tenant_id = a.tenant_id AND p.program_id = a.program_id
                 AND p.program_digest = a.program_digest AND p.status = 'active'
                WHERE c.execution_id = CAST(:execution_id AS uuid)
                  AND c.workload_spiffe_id = :workload_spiffe_id
                  AND c.claim_token = :claim_token
                  AND c.status = 'active' AND c.claim_until > now()
                  AND a.status = 'active'
                  AND r.status <> 'cancelled'
                  AND d.status = 'active'
                  AND c.deployment_incarnation = d.incarnation
                  AND m.status = 'active'
                  AND (a.membership_version IS NULL OR m.membership_version = a.membership_version)
                  AND a.revocation_epoch = d.revocation_epoch
            """), {"execution_id": execution_id,
                    "workload_spiffe_id": workload_spiffe_id,
                    "claim_token": claim_token}).mappings().one_or_none()
        return None if row is None else dict(row)

    def update_execution_status(
        self,
        *,
        execution_id: str,
        workload_spiffe_id: str,
        claim_token: str,
        status: str,
        pending_approval: dict[str, str] | None = None,
    ) -> bool:
        if status not in {"running", "retrying", "waiting_approval", "succeeded", "failed"}:
            raise ManagedSecurityError("managed execution status is invalid")
        durable_status = "running" if status == "retrying" else status
        with unit_of_work() as session:
            updated = session.execute(text("""
                UPDATE managed_runs r
                SET status = :status, updated_at = now()
                FROM managed_execution_claims c, managed_admissions a
                WHERE r.execution_id = CAST(:execution_id AS uuid)
                  AND c.execution_id = r.execution_id
                  AND a.execution_id = r.execution_id
                  AND c.workload_spiffe_id = :workload_spiffe_id
                  AND c.claim_token = :claim_token
                  AND c.status = 'active' AND c.claim_until > now()
                  AND a.status = 'active' AND r.status <> 'cancelled'
            """), {
                "execution_id": execution_id,
                "workload_spiffe_id": workload_spiffe_id,
                "claim_token": claim_token,
                "status": durable_status,
            })
            if updated.rowcount != 1:
                return False
            if status == "waiting_approval":
                if pending_approval is None:
                    raise ManagedSecurityError("waiting execution has no bound approval request")
                approval_row = session.execute(text("""
                    INSERT INTO managed_approval_requests
                    (execution_id, checkpoint_id, action, resource,
                     argument_digest, policy_version, status)
                    SELECT CAST(:execution_id AS uuid), :checkpoint_id, :action,
                           :resource, :argument_digest, a.policy_version, 'pending'
                    FROM managed_admissions a
                    WHERE a.execution_id = CAST(:execution_id AS uuid)
                      AND a.status = 'active'
                    ON CONFLICT (execution_id, checkpoint_id) DO UPDATE SET
                      action = EXCLUDED.action,
                      resource = EXCLUDED.resource,
                      argument_digest = EXCLUDED.argument_digest,
                      policy_version = EXCLUDED.policy_version,
                      requested_at = now()
                    WHERE managed_approval_requests.status = 'pending'
                      AND managed_approval_requests.action = EXCLUDED.action
                      AND managed_approval_requests.resource = EXCLUDED.resource
                      AND managed_approval_requests.argument_digest = EXCLUDED.argument_digest
                      AND managed_approval_requests.policy_version = EXCLUDED.policy_version
                    RETURNING checkpoint_id
                """), {
                    "execution_id": execution_id,
                    **pending_approval,
                }).one_or_none()
                if approval_row is None:
                    raise ManagedSecurityError("pending approval conflicts with durable request")
            if status in {"retrying", "succeeded", "failed"}:
                session.execute(text("""
                    UPDATE managed_execution_claims SET status = 'fenced'
                    WHERE execution_id = CAST(:execution_id AS uuid)
                      AND claim_token = :claim_token
                """), {"execution_id": execution_id, "claim_token": claim_token})
            return True

    def create(
        self,
        *,
        run_id: str,
        subject_id: str,
        run_kind: str,
        workflow_id: str,
        status: str,
        request: dict[str, Any],
        envelope: dict[str, Any],
        admission: Admission,
        outbox_payload: dict[str, Any],
    ) -> int:
        context = admission.context
        with unit_of_work() as session:
            session.execute(text("""
                INSERT INTO managed_admissions
                (admission_id, tenant_id, deployment_id, subject_id, execution_id,
                 workflow_id, workflow_digest, program_id, program_digest,
                 request_digest, revocation_epoch, issued_at, expires_at, status,
                 issuer, membership_version, policy_version)
                VALUES (CAST(:admission_id AS uuid), :tenant_id, :deployment_id,
                 :subject_id, CAST(:execution_id AS uuid), :workflow_id,
                 :workflow_digest, :program_id, :program_digest, :request_digest,
                 :revocation_epoch, :issued_at, :expires_at, :status,
                 :issuer, :membership_version, :policy_version)
                ON CONFLICT (admission_id) DO NOTHING
            """), {
                "admission_id": admission.admission_id,
                "tenant_id": context.tenant_id,
                "deployment_id": context.deployment_id,
                "subject_id": context.subject_id,
                "execution_id": self.execution_id(envelope),
                "workflow_id": admission.workflow_id,
                "workflow_digest": admission.workflow_digest,
                "program_id": admission.program_id,
                "program_digest": admission.program_digest,
                "request_digest": admission.request_digest,
                "revocation_epoch": admission.revocation_epoch,
                "issued_at": admission.issued_at,
                "expires_at": admission.expires_at,
                "status": admission.status,
                "issuer": context.issuer,
                "membership_version": context.membership_version,
                "policy_version": context.policy_version,
            })
            session.execute(text("""
                INSERT INTO managed_runs
                (run_id, execution_id, tenant_id, deployment_id, subject_id,
                 run_kind, workflow_id, status, request, envelope)
                VALUES (CAST(:run_id AS uuid), CAST(:execution_id AS uuid),
                 :tenant_id, :deployment_id, :subject_id, :run_kind, :workflow_id,
                 :status, CAST(:request AS jsonb), CAST(:envelope AS jsonb))
            """), {
                "run_id": run_id,
                "execution_id": self.execution_id(envelope),
                "tenant_id": context.tenant_id,
                "deployment_id": context.deployment_id,
                "subject_id": subject_id,
                "run_kind": run_kind,
                "workflow_id": workflow_id,
                "status": status,
                "request": json.dumps(request, sort_keys=True),
                "envelope": json.dumps(envelope, sort_keys=True),
            })
            session.execute(text("""
                INSERT INTO managed_execution_budgets (execution_id, remaining_units)
                VALUES (CAST(:execution_id AS uuid), 100)
                ON CONFLICT (execution_id) DO NOTHING
            """), {"execution_id": self.execution_id(envelope)})
            outbox = session.execute(text("""
                INSERT INTO managed_outbox (aggregate_id, event_type, payload)
                VALUES (CAST(:execution_id AS uuid), 'managed.run.admitted', CAST(:payload AS jsonb))
                RETURNING outbox_id
            """), {
                "execution_id": self.execution_id(envelope),
                "payload": json.dumps(outbox_payload, sort_keys=True),
            }).one()
            return int(outbox.outbox_id)

    def mark_outbox_published(self, outbox_id: int) -> None:
        with unit_of_work() as session:
            updated = session.execute(text("""
                UPDATE managed_outbox SET published_at = now()
                WHERE outbox_id = :outbox_id AND published_at IS NULL
            """), {"outbox_id": outbox_id})
            if updated.rowcount not in (0, 1):
                raise ManagedSecurityError("managed outbox acknowledgement is invalid")

    def pending_outbox(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Return unpublished queue events in commit order.

        The publisher uses a deterministic broker job ID derived from the
        outbox row, so selecting the same row after an API or broker restart is
        safe.  A locked dequeue is intentionally avoided: publication happens
        over the network and must not hold a database transaction open.
        """
        if limit <= 0 or limit > 1000:
            raise ManagedSecurityError("managed outbox batch size is invalid")
        from core.storage.connection import get_db_session

        with get_db_session() as session:
            rows = session.execute(text("""
                SELECT outbox_id, aggregate_id, event_type, payload
                FROM managed_outbox
                WHERE published_at IS NULL
                  AND event_type IN ('managed.run.admitted', 'managed.run.resumed')
                ORDER BY outbox_id
                LIMIT :limit
            """), {"limit": limit}).mappings().all()
        return [dict(row) for row in rows]

    def resume(
        self,
        *,
        run_id: str,
        tenant_id: str,
        subject_id: str,
        envelope: QueueEnvelope,
        outbox_payload: dict[str, Any],
    ) -> int:
        """Persist a renewed signed resume and outbox row in one transaction."""
        admission = envelope.admission
        with unit_of_work() as session:
            claimable = session.execute(text("""
                SELECT 1
                FROM managed_admissions a
                JOIN managed_runs r ON r.execution_id = a.execution_id
                JOIN managed_deployments d ON d.deployment_id = a.deployment_id
                JOIN managed_memberships m
                  ON m.tenant_id = a.tenant_id AND m.subject_id = a.subject_id
                 AND m.issuer = a.issuer
                JOIN managed_program_registry p
                  ON p.tenant_id = a.tenant_id AND p.program_id = a.program_id
                 AND p.program_digest = a.program_digest
                WHERE r.run_id = CAST(:run_id AS uuid)
                  AND r.tenant_id = :tenant_id AND r.subject_id = :subject_id
                  AND r.status IN ('waiting_approval', 'approved', 'failed')
                  AND NOT EXISTS (
                    SELECT 1 FROM agent_events e
                    WHERE e.run_id = r.run_id AND e.kind = 'terminal'
                  )
                  AND a.admission_id = CAST(:admission_id AS uuid)
                  AND a.execution_id = CAST(:execution_id AS uuid)
                  AND a.workflow_id = :workflow_id
                  AND a.workflow_digest = :workflow_digest
                  AND a.program_id = :program_id
                  AND a.program_digest = :program_digest
                  AND a.request_digest = :request_digest
                  AND a.status = 'active'
                  AND d.status = 'active' AND d.revocation_epoch = a.revocation_epoch
                  AND m.status = 'active' AND m.membership_version = a.membership_version
                  AND p.status = 'active'
                FOR UPDATE OF a, r
            """), {
                "run_id": run_id,
                "tenant_id": tenant_id,
                "subject_id": subject_id,
                "admission_id": admission.admission_id,
                "execution_id": envelope.execution_id,
                "workflow_id": admission.workflow_id,
                "workflow_digest": admission.workflow_digest,
                "program_id": admission.program_id,
                "program_digest": admission.program_digest,
                "request_digest": admission.request_digest,
            }).one_or_none()
            if claimable is None:
                raise ManagedSecurityError("managed run is not resumable")
            session.execute(text("""
                UPDATE managed_admissions
                SET issued_at = :issued_at, expires_at = :expires_at
                WHERE admission_id = CAST(:admission_id AS uuid)
            """), {
                "issued_at": admission.issued_at,
                "expires_at": admission.expires_at,
                "admission_id": admission.admission_id,
            })
            session.execute(text("""
                UPDATE managed_runs
                SET status = 'queued', envelope = CAST(:envelope AS jsonb), updated_at = now()
                WHERE run_id = CAST(:run_id AS uuid)
            """), {
                "run_id": run_id,
                "envelope": json.dumps(envelope.as_dict(), sort_keys=True),
            })
            outbox = session.execute(text("""
                INSERT INTO managed_outbox (aggregate_id, event_type, payload)
                VALUES (CAST(:execution_id AS uuid), 'managed.run.resumed', CAST(:payload AS jsonb))
                RETURNING outbox_id
            """), {
                "execution_id": envelope.execution_id,
                "payload": json.dumps(outbox_payload, sort_keys=True),
            }).one()
            return int(outbox.outbox_id)

    @staticmethod
    def execution_id(envelope: dict[str, Any]) -> str:
        return str(envelope["execution_id"])

    def get(self, run_id: str, tenant_id: str, subject_id: str) -> dict[str, Any] | None:
        from core.storage.connection import get_db_session

        with get_db_session() as session:
            row = session.execute(text("""
                SELECT run_id, execution_id, tenant_id, deployment_id, subject_id,
                       status, workflow_id FROM managed_runs
                WHERE run_id = CAST(:run_id AS uuid) AND tenant_id = :tenant_id
                  AND subject_id = :subject_id
            """), {"run_id": run_id, "tenant_id": tenant_id, "subject_id": subject_id}).mappings().one_or_none()
        return None if row is None else dict(row)

    def list(self, tenant_id: str, subject_id: str) -> list[dict[str, Any]]:
        from core.storage.connection import get_db_session

        with get_db_session() as session:
            rows = session.execute(text("""
                SELECT run_id, execution_id, tenant_id, deployment_id, subject_id,
                       status, workflow_id FROM managed_runs
                WHERE tenant_id = :tenant_id AND subject_id = :subject_id
                ORDER BY run_id
            """), {"tenant_id": tenant_id, "subject_id": subject_id}).mappings().all()
        return [dict(row) for row in rows]

    def owner(self, run_id: str, tenant_id: str) -> str | None:
        from core.storage.connection import get_db_session

        with get_db_session() as session:
            row = session.execute(text("""
                SELECT subject_id FROM managed_runs
                WHERE run_id = CAST(:run_id AS uuid) AND tenant_id = :tenant_id
            """), {"run_id": run_id, "tenant_id": tenant_id}).one_or_none()
        return None if row is None else str(row.subject_id)

    def get_for_tenant(self, run_id: str, tenant_id: str) -> dict[str, Any] | None:
        from core.storage.connection import get_db_session

        with get_db_session() as session:
            row = session.execute(text("""
                SELECT run_id, execution_id, tenant_id, deployment_id, subject_id,
                       status, workflow_id FROM managed_runs
                WHERE run_id = CAST(:run_id AS uuid) AND tenant_id = :tenant_id
            """), {"run_id": run_id, "tenant_id": tenant_id}).mappings().one_or_none()
        return None if row is None else dict(row)

    def approval_active(
        self,
        *,
        execution_id: str,
        action: str,
        resource: str,
        argument_digest: str,
        policy_version: str,
    ) -> bool:
        from core.storage.connection import get_db_session

        with get_db_session() as session:
            row = session.execute(text("""
                SELECT 1 FROM managed_approvals
                WHERE execution_id = CAST(:execution_id AS uuid)
                  AND action = :action AND resource = :resource
                  AND argument_digest = :argument_digest
                  AND policy_version = :policy_version
                  AND status = 'approved' AND expires_at > now()
            """), {
                "execution_id": execution_id,
                "action": action,
                "resource": resource,
                "argument_digest": argument_digest,
                "policy_version": policy_version,
            }).one_or_none()
        return row is not None

    def envelope(self, run_id: str, tenant_id: str, subject_id: str) -> dict[str, Any] | None:
        import json
        from core.storage.connection import get_db_session

        with get_db_session() as session:
            row = session.execute(text("""
                SELECT envelope FROM managed_runs
                WHERE run_id = CAST(:run_id AS uuid) AND tenant_id = :tenant_id
                  AND subject_id = :subject_id
            """), {"run_id": run_id, "tenant_id": tenant_id, "subject_id": subject_id}).one_or_none()
        if row is None:
            return None
        value = row.envelope
        return value if isinstance(value, dict) else json.loads(value)

    def update_status(self, run_id: str, tenant_id: str, subject_id: str, status: str) -> dict[str, Any] | None:
        from core.storage.connection import get_db_session

        with unit_of_work() as session:
            session.execute(text("""
                UPDATE managed_runs SET status = :status, updated_at = now()
                WHERE run_id = CAST(:run_id AS uuid) AND tenant_id = :tenant_id
                  AND subject_id = :subject_id
            """), {"run_id": run_id, "tenant_id": tenant_id, "subject_id": subject_id, "status": status})
        return self.get(run_id, tenant_id, subject_id)

    def cancel(self, run_id: str, tenant_id: str, subject_id: str, execution_id: str) -> dict[str, Any] | None:
        from core.storage.connection import get_db_session

        with unit_of_work() as session:
            session.execute(text("""
                UPDATE managed_runs SET status = 'cancelled', updated_at = now()
                WHERE run_id = CAST(:run_id AS uuid) AND tenant_id = :tenant_id
                  AND subject_id = :subject_id
            """), {"run_id": run_id, "tenant_id": tenant_id, "subject_id": subject_id})
            session.execute(text("""
                UPDATE managed_admissions SET status = 'revoked'
                WHERE execution_id = CAST(:execution_id AS uuid)
            """), {"execution_id": execution_id})
            session.execute(text("""
                UPDATE managed_execution_claims SET status = 'cancelled'
                WHERE execution_id = CAST(:execution_id AS uuid)
            """), {"execution_id": execution_id})
            session.execute(text("""
                INSERT INTO managed_outbox (aggregate_id, event_type, payload)
                VALUES (CAST(:execution_id AS uuid), 'managed.run.cancelled', CAST(:payload AS jsonb))
            """), {"execution_id": execution_id, "payload": json.dumps({"run_id": run_id})})
        return self.get(run_id, tenant_id, subject_id)

    def approve(
        self,
        *,
        run_id: str,
        tenant_id: str,
        owner_subject_id: str,
        execution_id: str,
        approver_subject_id: str,
        action: str,
        resource: str,
        argument_digest: str,
        policy_version: str,
        checkpoint_id: str,
    ) -> dict[str, Any] | None:
        import uuid

        with unit_of_work() as session:
            pending = session.execute(text("""
                SELECT q.action, q.resource, q.argument_digest, q.policy_version
                FROM managed_runs r
                JOIN managed_admissions a ON a.execution_id = r.execution_id
                JOIN managed_deployments d ON d.deployment_id = r.deployment_id
                JOIN managed_approval_requests q ON q.execution_id = r.execution_id
                WHERE r.run_id = CAST(:run_id AS uuid)
                  AND r.execution_id = CAST(:execution_id AS uuid)
                  AND r.tenant_id = :tenant_id
                  AND r.subject_id = :owner_subject_id
                  AND r.status = 'waiting_approval'
                  AND q.checkpoint_id = :checkpoint_id
                  AND q.status = 'pending'
                  AND q.action = :action
                  AND q.resource = :resource
                  AND q.argument_digest = :argument_digest
                  AND q.policy_version = :policy_version
                  AND a.status = 'active'
                  AND a.policy_version = :policy_version
                  AND d.status = 'active'
                  AND d.revocation_epoch = a.revocation_epoch
                FOR UPDATE OF r
            """), {
                "run_id": run_id,
                "execution_id": execution_id,
                "tenant_id": tenant_id,
                "owner_subject_id": owner_subject_id,
                "policy_version": policy_version,
                "checkpoint_id": checkpoint_id,
                "action": action,
                "resource": resource,
                "argument_digest": argument_digest,
            }).mappings().one_or_none()
            if pending is None:
                raise ManagedSecurityError("managed run is not awaiting approval")
            session.execute(text("""
                INSERT INTO managed_approvals
                (approval_id, execution_id, approver_subject_id, checkpoint_id,
                 action, resource, argument_digest, policy_version, expires_at)
                VALUES (CAST(:approval_id AS uuid), CAST(:execution_id AS uuid),
                 :approver, :checkpoint_id, :action, :resource, :argument_digest, :policy_version,
                 now() + interval '60 seconds')
            """), {
                "approval_id": str(uuid.uuid4()),
                "execution_id": execution_id,
                "approver": approver_subject_id,
                "checkpoint_id": checkpoint_id,
                "action": action,
                "resource": resource,
                "argument_digest": argument_digest,
                "policy_version": policy_version,
            })
            session.execute(text("""
                UPDATE managed_approval_requests
                SET status = 'approved', resolved_at = now()
                WHERE execution_id = CAST(:execution_id AS uuid)
                  AND checkpoint_id = :checkpoint_id AND status = 'pending'
            """), {"execution_id": execution_id, "checkpoint_id": checkpoint_id})
            session.execute(text("""
                UPDATE managed_runs SET status = 'approved', updated_at = now()
                WHERE run_id = CAST(:run_id AS uuid) AND tenant_id = :tenant_id
                  AND subject_id = :owner_subject_id
            """), {
                "run_id": run_id,
                "tenant_id": tenant_id,
                "owner_subject_id": owner_subject_id,
            })
        # The approver is deliberately distinct from the requesting owner.
        # Transition the owner's run while retaining the approver in the
        # approval record above; using the approver as the owner would make a
        # valid approval appear to succeed without changing the durable run.
        return self.get(run_id, tenant_id, owner_subject_id)

    def approved_decisions(
        self,
        *,
        execution_id: str,
        workload_spiffe_id: str,
        claim_token: str,
    ) -> list[dict[str, Any]] | None:
        """Return decisions only for the currently authenticated execution claim."""
        if self.authorization_context(execution_id, workload_spiffe_id, claim_token) is None:
            return None
        from core.storage.connection import get_db_session

        with get_db_session() as session:
            rows = session.execute(text("""
                SELECT q.checkpoint_id, a.approver_subject_id, a.created_at
                FROM managed_approval_requests q
                JOIN managed_approvals a
                  ON a.execution_id = q.execution_id
                 AND a.checkpoint_id = q.checkpoint_id
                WHERE q.execution_id = CAST(:execution_id AS uuid)
                  AND q.status = 'approved'
                  AND a.status = 'approved' AND a.expires_at > now()
                ORDER BY a.created_at
            """), {"execution_id": execution_id}).mappings().all()
        return [dict(row) for row in rows]
