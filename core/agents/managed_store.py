"""Durable managed-run repository.

The managed API uses this repository for admission, lifecycle state, and the
outbox record. Worker SQL credentials are denied these tables by migration.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Iterable

from sqlalchemy import text

from core.agents.managed_execution import Admission, ManagedSecurityError
from core.storage.unit_of_work import unit_of_work


class ManagedRunStore:
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

    def record_claim(self, execution_id: str, worker_key_id: str, claim_token: str, claim_until: Any) -> None:
        with unit_of_work() as session:
            session.execute(text("""
                UPDATE managed_execution_claims SET status = 'fenced'
                WHERE execution_id = CAST(:execution_id AS uuid) AND status = 'active'
            """), {"execution_id": execution_id})
            session.execute(text("""
                INSERT INTO managed_execution_claims
                (execution_id, worker_key_id, claim_token, claim_version, claim_until, status)
                VALUES (CAST(:execution_id AS uuid), :worker_key_id, :claim_token,
                        (SELECT COALESCE(MAX(claim_version), 0) + 1
                         FROM managed_execution_claims
                         WHERE execution_id = CAST(:execution_id AS uuid)),
                        :claim_until, 'active')
                ON CONFLICT (execution_id) DO UPDATE SET
                  worker_key_id = EXCLUDED.worker_key_id,
                  claim_token = EXCLUDED.claim_token,
                  claim_version = managed_execution_claims.claim_version + 1,
                  claim_until = EXCLUDED.claim_until,
                  status = 'active'
            """), {"execution_id": execution_id, "worker_key_id": worker_key_id,
                    "claim_token": claim_token, "claim_until": claim_until})

    def claim_active(self, execution_id: str, worker_key_id: str, claim_token: str) -> bool:
        from core.storage.connection import get_db_session

        with get_db_session() as session:
            row = session.execute(text("""
                SELECT 1 FROM managed_execution_claims
                WHERE execution_id = CAST(:execution_id AS uuid)
                  AND worker_key_id = :worker_key_id AND claim_token = :claim_token
                  AND status = 'active' AND claim_until > now()
            """), {"execution_id": execution_id, "worker_key_id": worker_key_id,
                    "claim_token": claim_token}).one_or_none()
        return row is not None

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
    ) -> None:
        context = admission.context
        with unit_of_work() as session:
            session.execute(text("""
                INSERT INTO managed_admissions
                (admission_id, tenant_id, deployment_id, subject_id, execution_id,
                 workflow_id, workflow_digest, program_id, program_digest,
                 request_digest, revocation_epoch, issued_at, expires_at, status)
                VALUES (CAST(:admission_id AS uuid), :tenant_id, :deployment_id,
                 :subject_id, CAST(:execution_id AS uuid), :workflow_id,
                 :workflow_digest, :program_id, :program_digest, :request_digest,
                 :revocation_epoch, :issued_at, :expires_at, :status)
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
                INSERT INTO managed_outbox (aggregate_id, event_type, payload)
                VALUES (CAST(:execution_id AS uuid), 'managed.run.admitted', CAST(:payload AS jsonb))
            """), {"execution_id": self.execution_id(envelope), "payload": json.dumps({"run_id": run_id})})

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
    ) -> dict[str, Any] | None:
        import uuid

        with unit_of_work() as session:
            session.execute(text("""
                INSERT INTO managed_approvals
                (approval_id, execution_id, approver_subject_id, action, resource,
                 argument_digest, policy_version, expires_at)
                VALUES (CAST(:approval_id AS uuid), CAST(:execution_id AS uuid),
                 :approver, :action, :resource, :argument_digest, :policy_version,
                 now() + interval '60 seconds')
            """), {
                "approval_id": str(uuid.uuid4()),
                "execution_id": execution_id,
                "approver": approver_subject_id,
                "action": action,
                "resource": resource,
                "argument_digest": argument_digest,
                "policy_version": policy_version,
            })
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
