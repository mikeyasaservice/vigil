from __future__ import annotations

import base64
import binascii
import json
import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

import psycopg2
from psycopg2.extras import RealDictCursor

from core.agents.managed_execution import managed_digest
from core.agents.managed_execution import Ed25519Verifier, ManagedSecurityError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from services.management.auth import OperatorIdentity
from services.management.contracts import DeploymentManifest


class ManagementError(ValueError):
    code = "management_invalid"


class ManagementDenied(ManagementError):
    code = "management_denied"


class ManagementConflict(ManagementError):
    code = "management_conflict"


class ManagementUnavailable(RuntimeError):
    code = "management_unavailable"


def manifest_digest(manifest: DeploymentManifest) -> str:
    return managed_digest(manifest.model_dump(mode="json"))


class ManagementStore:
    def __init__(self, database_url: str | None = None):
        self.database_url = database_url or os.getenv("MANAGEMENT_DATABASE_URL", "")
        if not self.database_url:
            raise ManagementUnavailable("management database is not configured")

    def check_ready(self) -> None:
        with self._transaction() as cursor:
            cursor.execute("SELECT 1")
            if cursor.fetchone() is None:
                raise ManagementUnavailable("management database readiness check failed")

    @contextmanager
    def _transaction(self) -> Iterator[Any]:
        try:
            connection = psycopg2.connect(self.database_url, connect_timeout=5)
        except psycopg2.Error as exc:
            raise ManagementUnavailable("management database is unavailable") from exc
        try:
            with connection:
                with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                    yield cursor
        except psycopg2.Error as exc:
            raise ManagementUnavailable("management state transaction failed") from exc
        finally:
            connection.close()

    @staticmethod
    def _scope(cursor, actor: OperatorIdentity, tenant_id: str, roles: tuple[str, ...]) -> None:
        cursor.execute(
            """
            SELECT 1
              FROM management_operator_scopes
             WHERE issuer = %(issuer)s AND subject_id = %(subject)s
               AND status = 'active' AND role = ANY(%(roles)s)
               AND (tenant_id = %(tenant)s OR tenant_id IS NULL)
             LIMIT 1
            """,
            {"issuer": actor.issuer, "subject": actor.subject_id, "tenant": tenant_id, "roles": list(roles)},
        )
        if cursor.fetchone() is None:
            raise ManagementDenied("operator is not authorized for this tenant operation")

    @staticmethod
    def _binding(cursor, manifest: DeploymentManifest) -> dict[str, Any]:
        cursor.execute(
            """
            SELECT * FROM management_account_bindings
             WHERE binding_ref = %(binding)s AND tenant_id = %(tenant)s
               AND deployment_id = %(deployment)s AND provider = 'aws'
               AND account_id = substring(role_arn from 'arn:aws:iam::([0-9]{12}):role/')
               AND region = %(region)s
               AND network_binding_ref = %(network)s
               AND state_binding_ref = %(state)s
               AND status = 'active'
             FOR SHARE
            """,
            {
                "binding": manifest.placement.account_binding_ref,
                "tenant": manifest.tenant_id,
                "deployment": manifest.deployment_id,
                "region": manifest.placement.region,
                "network": manifest.placement.network_binding_ref,
                "state": manifest.placement.state_binding_ref,
            },
        )
        row = cursor.fetchone()
        if row is None:
            raise ManagementDenied("deployment target is not an active trusted binding")
        return dict(row)

    @staticmethod
    def _artifacts(cursor, manifest: DeploymentManifest) -> None:
        required = {
            manifest.releases.application.digest_ref: "application",
            manifest.releases.harness.digest_ref: "harness",
            manifest.releases.infrastructure.digest_ref: "infrastructure",
            manifest.releases.policy.digest_ref: "policy",
            manifest.releases.dspy.digest_ref: "dspy",
            manifest.operations.rollback_compatibility_ref: "compatibility",
        }
        cursor.execute(
            """
            SELECT digest_ref, artifact_kind FROM management_artifact_approvals
             WHERE digest_ref = ANY(%(digests)s) AND status = 'approved'
            """,
            {"digests": list(required)},
        )
        held = {str(row["digest_ref"]): str(row["artifact_kind"]) for row in cursor.fetchall()}
        if held != required:
            raise ManagementDenied("manifest contains an unapproved or incorrectly classified artifact")

    def submit_operation(
        self,
        manifest: DeploymentManifest,
        operation_kind: str,
        idempotency_key: str,
        actor: OperatorIdentity,
    ) -> dict[str, Any]:
        if not idempotency_key or len(idempotency_key) > 200:
            raise ManagementError("a bounded idempotency key is required")
        digest = manifest_digest(manifest)
        operation_id = uuid.uuid4()
        with self._transaction() as cursor:
            self._scope(cursor, actor, manifest.tenant_id, ("platform_admin", "deployment_operator"))
            binding = self._binding(cursor, manifest)
            self._artifacts(cursor, manifest)
            cursor.execute(
                """
                SELECT * FROM management_operations
                 WHERE deployment_id = %(deployment)s AND idempotency_key = %(idempotency)s
                 FOR UPDATE
                """,
                {"deployment": manifest.deployment_id, "idempotency": idempotency_key},
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing["manifest_digest"] != digest or existing["operation_kind"] != operation_kind:
                    raise ManagementConflict("idempotency key was already used for different work")
                return dict(existing)
            cursor.execute(
                """
                SELECT * FROM management_deployments
                 WHERE deployment_id = %(deployment)s
                 FOR UPDATE
                """,
                {"deployment": manifest.deployment_id},
            )
            deployment = cursor.fetchone()
            if deployment is None:
                if operation_kind != "provision" or manifest.expected_generation != 0:
                    raise ManagementConflict("unregistered deployment requires generation-zero provision")
                cursor.execute(
                    """
                    INSERT INTO management_deployments
                      (deployment_id, tenant_id, binding_ref, incarnation,
                       desired_generation, observed_generation, next_fencing_token)
                    VALUES (%(deployment)s, %(tenant)s, %(binding)s, %(incarnation)s, 0, 0, 1)
                    RETURNING *
                    """,
                    {
                        "deployment": manifest.deployment_id,
                        "tenant": manifest.tenant_id,
                        "binding": manifest.placement.account_binding_ref,
                        "incarnation": str(manifest.incarnation),
                    },
                )
                deployment = cursor.fetchone()
            if (
                deployment["tenant_id"] != manifest.tenant_id
                or deployment["binding_ref"] != manifest.placement.account_binding_ref
                or str(deployment["incarnation"]) != str(manifest.incarnation)
            ):
                raise ManagementDenied("manifest identity does not match the registered deployment")
            if int(deployment["desired_generation"]) != manifest.expected_generation:
                raise ManagementConflict("manifest expected generation is stale")
            cursor.execute(
                """
                SELECT 1 FROM management_operations
                 WHERE deployment_id = %(deployment)s
                   AND status IN ('planning', 'awaiting_approval', 'approved', 'claimed', 'applying', 'verifying', 'recovery_required')
                 LIMIT 1
                """,
                {"deployment": manifest.deployment_id},
            )
            if cursor.fetchone() is not None:
                raise ManagementConflict("deployment already has a mutating operation")
            fence = int(deployment["next_fencing_token"])
            manifest_json = json.dumps(manifest.model_dump(mode="json"), separators=(",", ":"), sort_keys=True)
            cursor.execute(
                """
                UPDATE management_deployments
                   SET desired_generation = %(generation)s,
                       desired_manifest = CAST(%(manifest)s AS jsonb),
                       desired_manifest_digest = %(digest)s,
                       state = 'planning', next_fencing_token = %(next_fence)s,
                       updated_at = now()
                 WHERE deployment_id = %(deployment)s
                """,
                {
                    "generation": manifest.generation,
                    "manifest": manifest_json,
                    "digest": digest,
                    "next_fence": fence + 1,
                    "deployment": manifest.deployment_id,
                },
            )
            cursor.execute(
                """
                INSERT INTO management_operations
                  (operation_id, deployment_id, tenant_id, idempotency_key,
                   operation_kind, manifest_digest, binding_digest, expected_generation,
                   target_generation, fencing_token, actor_issuer, actor_subject)
                VALUES (CAST(%(operation)s AS uuid), %(deployment)s, %(tenant)s,
                        %(idempotency)s, %(kind)s, %(digest)s, %(binding_digest)s, %(expected)s,
                        %(target)s, %(fence)s, %(issuer)s, %(subject)s)
                RETURNING *
                """,
                {
                    "operation": str(operation_id),
                    "deployment": manifest.deployment_id,
                    "tenant": manifest.tenant_id,
                    "idempotency": idempotency_key,
                    "kind": operation_kind,
                    "digest": digest,
                    "binding_digest": binding["binding_digest"],
                    "expected": manifest.expected_generation,
                    "target": manifest.generation,
                    "fence": fence,
                    "issuer": actor.issuer,
                    "subject": actor.subject_id,
                },
            )
            operation = dict(cursor.fetchone())
            event = {"manifest_digest": digest, "target_generation": manifest.generation, "fencing_token": fence}
            cursor.execute(
                """
                INSERT INTO management_operation_events (operation_id, sequence, event_type, payload)
                VALUES (CAST(%(operation)s AS uuid), 1, 'operation.requested', CAST(%(payload)s AS jsonb));
                INSERT INTO management_outbox (aggregate_id, event_type, payload)
                VALUES (CAST(%(operation)s AS uuid), 'management.operation.plan_requested', CAST(%(payload)s AS jsonb))
                """,
                {"operation": str(operation_id), "payload": json.dumps(event, separators=(",", ":"))},
            )
            return operation

    def get_operation(self, operation_id: str, actor: OperatorIdentity) -> dict[str, Any] | None:
        with self._transaction() as cursor:
            cursor.execute("SELECT * FROM management_operations WHERE operation_id = CAST(%s AS uuid)", (operation_id,))
            row = cursor.fetchone()
            if row is None:
                return None
            self._scope(cursor, actor, str(row["tenant_id"]), ("platform_admin", "deployment_operator", "deployment_approver", "auditor"))
            return dict(row)

    def get_deployment(self, deployment_id: str, actor: OperatorIdentity) -> dict[str, Any] | None:
        with self._transaction() as cursor:
            cursor.execute("SELECT * FROM management_deployments WHERE deployment_id = %s", (deployment_id,))
            row = cursor.fetchone()
            if row is None:
                return None
            self._scope(cursor, actor, str(row["tenant_id"]), ("platform_admin", "deployment_operator", "deployment_approver", "auditor"))
            return dict(row)

    def approve_operation(
        self,
        operation_id: str,
        actor: OperatorIdentity,
        manifest_digest_value: str,
        plan_hash: str,
        expires_at: datetime,
    ) -> dict[str, Any]:
        if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
            raise ManagementError("approval expiry must be in the future")
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT * FROM management_operations WHERE operation_id = CAST(%s AS uuid) FOR UPDATE",
                (operation_id,),
            )
            operation = cursor.fetchone()
            if operation is None:
                raise ManagementError("operation was not found")
            self._scope(cursor, actor, str(operation["tenant_id"]), ("platform_admin", "deployment_approver"))
            if operation["actor_issuer"] == actor.issuer and operation["actor_subject"] == actor.subject_id:
                raise ManagementDenied("deployment requester cannot approve the same operation")
            if operation["status"] != "awaiting_approval":
                raise ManagementConflict("operation is not awaiting approval")
            if operation["manifest_digest"] != manifest_digest_value or operation["plan_hash"] != plan_hash:
                raise ManagementConflict("approval does not match the current manifest and plan")
            cursor.execute(
                """
                INSERT INTO management_operation_approvals
                  (operation_id, manifest_digest, plan_hash, approver_issuer, approver_subject, expires_at)
                VALUES (CAST(%(operation)s AS uuid), %(manifest)s, %(plan)s, %(issuer)s, %(subject)s, %(expires)s)
                ON CONFLICT (operation_id) DO NOTHING
                """,
                {
                    "operation": operation_id,
                    "manifest": manifest_digest_value,
                    "plan": plan_hash,
                    "issuer": actor.issuer,
                    "subject": actor.subject_id,
                    "expires": expires_at,
                },
            )
            if cursor.rowcount != 1:
                raise ManagementConflict("operation already has an approval")
            cursor.execute(
                "UPDATE management_operations SET status = 'approved', updated_at = now() WHERE operation_id = CAST(%s AS uuid) RETURNING *",
                (operation_id,),
            )
            approved = dict(cursor.fetchone())
            cursor.execute(
                """
                INSERT INTO management_operation_events (operation_id, sequence, event_type, payload)
                SELECT CAST(%(operation)s AS uuid), COALESCE(max(sequence), 0) + 1,
                       'operation.approved', CAST(%(payload)s AS jsonb)
                  FROM management_operation_events WHERE operation_id = CAST(%(operation)s AS uuid)
                """,
                {
                    "operation": operation_id,
                    "payload": json.dumps({"approver_issuer": actor.issuer, "approver_subject": actor.subject_id, "plan_hash": plan_hash}),
                },
            )
            return approved

    def claim_reconcile(
        self,
        operation_id: str,
        workload_spiffe_id: str,
        runner_id: str,
        phase: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        with self._transaction() as cursor:
            cursor.execute(
                """
                SELECT o.*, d.desired_manifest, d.desired_manifest_digest,
                       d.next_fencing_token, b.reconciler_spiffe_id
                  FROM management_operations o
                  JOIN management_deployments d USING (deployment_id)
                  JOIN management_account_bindings b ON b.binding_ref = d.binding_ref
                 WHERE o.operation_id = CAST(%s AS uuid)
                 FOR UPDATE OF o, d
                """,
                (operation_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise ManagementError("operation was not found")
            if row["reconciler_spiffe_id"] != workload_spiffe_id:
                raise ManagementDenied("reconciler workload is not bound to this deployment")
            if int(row["fencing_token"]) != int(row["next_fencing_token"]) - 1:
                raise ManagementConflict("operation was fenced by newer deployment work")
            if row["manifest_digest"] != row["desired_manifest_digest"]:
                raise ManagementConflict("desired manifest changed after operation admission")
            expected_status = "planning" if phase == "plan" else "approved"
            reclaimable = (
                row["status"] == "claimed"
                and row["claimed_phase"] == phase
                and row["lease_expires_at"] is not None
                and row["lease_expires_at"] <= datetime.now(timezone.utc)
            )
            retryable = row["status"] == "recovery_required" and row["claimed_phase"] == phase
            if row["status"] != expected_status and not reclaimable and not retryable:
                raise ManagementConflict(f"operation is not ready for {phase}")
            if phase == "apply":
                cursor.execute(
                    """
                    SELECT 1 FROM management_operation_approvals
                     WHERE operation_id = CAST(%s AS uuid)
                       AND manifest_digest = %s AND plan_hash = %s
                       AND expires_at > now()
                    """,
                    (operation_id, row["manifest_digest"], row["plan_hash"]),
                )
                if cursor.fetchone() is None:
                    raise ManagementDenied("operation has no current matching approval")
            command_id = uuid.uuid4()
            cursor.execute(
                """
                UPDATE management_operations
                   SET status = 'claimed', claimed_by = %(runner)s,
                       claimed_phase = %(phase)s,
                       claim_command_id = CAST(%(command)s AS uuid),
                       claimed_at = now(), lease_expires_at = now() + interval '10 minutes',
                       attempt_count = attempt_count + 1, updated_at = now()
                 WHERE operation_id = CAST(%(operation)s AS uuid)
                 RETURNING *
                """,
                {"operation": operation_id, "runner": runner_id, "phase": phase, "command": str(command_id)},
            )
            operation = dict(cursor.fetchone())
            cursor.execute(
                """
                INSERT INTO management_operation_events (operation_id, sequence, event_type, payload)
                SELECT CAST(%(operation)s AS uuid), COALESCE(max(sequence), 0) + 1,
                       %(event)s, CAST(%(payload)s AS jsonb)
                  FROM management_operation_events WHERE operation_id = CAST(%(operation)s AS uuid)
                """,
                {
                    "operation": operation_id,
                    "event": f"operation.{phase}_claimed",
                    "payload": json.dumps(
                        {
                            "runner_id": runner_id,
                            "command_id": str(operation["claim_command_id"]),
                            "fencing_token": operation["fencing_token"],
                        }
                    ),
                },
            )
            return operation, dict(row["desired_manifest"])

    def record_plan(
        self,
        operation_id: str,
        workload_spiffe_id: str,
        runner_id: str,
        command_id: str,
        fencing_token: int,
        digest: str,
        plan_hash: str,
    ) -> dict[str, Any]:
        with self._transaction() as cursor:
            cursor.execute(
                """
                SELECT o.*, b.reconciler_spiffe_id
                  FROM management_operations o
                  JOIN management_deployments d USING (deployment_id)
                  JOIN management_account_bindings b ON b.binding_ref = d.binding_ref
                 WHERE o.operation_id = CAST(%s AS uuid)
                 FOR UPDATE OF o
                """,
                (operation_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise ManagementError("operation was not found")
            if row["reconciler_spiffe_id"] != workload_spiffe_id or row["claimed_by"] != runner_id:
                raise ManagementDenied("plan result is not from the current bound claimant")
            if str(row["claim_command_id"]) != command_id:
                raise ManagementConflict("plan command is stale")
            if row["status"] != "claimed" or row["claimed_phase"] != "plan" or int(row["fencing_token"]) != fencing_token:
                raise ManagementConflict("plan claimant is stale")
            if row["lease_expires_at"] is None or row["lease_expires_at"] <= datetime.now(timezone.utc):
                raise ManagementConflict("plan claimant lease expired")
            if row["manifest_digest"] != digest:
                raise ManagementConflict("plan digest does not match admitted manifest")
            cursor.execute(
                """
                UPDATE management_operations
                   SET plan_hash = %(plan)s, status = 'awaiting_approval',
                       claimed_by = NULL, claimed_phase = NULL, claimed_at = NULL, lease_expires_at = NULL,
                       claim_command_id = NULL,
                       updated_at = now()
                 WHERE operation_id = CAST(%(operation)s AS uuid)
                 RETURNING *
                """,
                {"operation": operation_id, "plan": plan_hash},
            )
            operation = dict(cursor.fetchone())
            cursor.execute(
                "UPDATE management_deployments SET state = 'awaiting_approval', updated_at = now() WHERE deployment_id = %s",
                (operation["deployment_id"],),
            )
            payload = json.dumps(
                {"command_id": command_id, "manifest_digest": digest, "plan_hash": plan_hash}, separators=(",", ":")
            )
            cursor.execute(
                """
                INSERT INTO management_operation_events (operation_id, sequence, event_type, payload)
                SELECT CAST(%(operation)s AS uuid), COALESCE(max(sequence), 0) + 1,
                       'operation.plan_ready', CAST(%(payload)s AS jsonb)
                  FROM management_operation_events WHERE operation_id = CAST(%(operation)s AS uuid);
                INSERT INTO management_outbox (aggregate_id, event_type, payload)
                VALUES (CAST(%(operation)s AS uuid), 'management.operation.approval_required', CAST(%(payload)s AS jsonb))
                """,
                {"operation": operation_id, "payload": payload},
            )
            return operation

    def complete_operation(
        self,
        operation_id: str,
        workload_spiffe_id: str,
        runner_id: str,
        receipt: dict[str, Any],
    ) -> dict[str, Any]:
        with self._transaction() as cursor:
            cursor.execute(
                """
                SELECT o.*, d.next_fencing_token, b.reconciler_spiffe_id, b.receipt_public_key
                  FROM management_operations o
                  JOIN management_deployments d USING (deployment_id)
                  JOIN management_account_bindings b ON b.binding_ref = d.binding_ref
                 WHERE o.operation_id = CAST(%s AS uuid)
                 FOR UPDATE OF o, d
                """,
                (operation_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise ManagementError("operation was not found")
            if row["reconciler_spiffe_id"] != workload_spiffe_id or row["claimed_by"] != runner_id:
                raise ManagementDenied("receipt is not from the current bound claimant")
            if row["status"] != "claimed" or row["claimed_phase"] != "apply" or int(row["next_fencing_token"]) - 1 != int(row["fencing_token"]):
                raise ManagementConflict("receipt claimant is stale")
            if row["lease_expires_at"] is None or row["lease_expires_at"] <= datetime.now(timezone.utc):
                raise ManagementConflict("receipt claimant lease expired")
            signature = str(receipt.pop("signature", ""))
            expected = {
                "operation_id": str(row["operation_id"]),
                "command_id": str(row["claim_command_id"]),
                "deployment_id": str(row["deployment_id"]),
                "tenant_id": str(row["tenant_id"]),
                "fencing_token": int(row["fencing_token"]),
                "manifest_digest": str(row["manifest_digest"]),
                "plan_hash": str(row["plan_hash"]),
                "observed_generation": int(row["target_generation"]),
            }
            if any(receipt.get(key) != value for key, value in expected.items()):
                raise ManagementConflict("receipt does not match the claimed operation")
            try:
                encoded_key = str(row["receipt_public_key"])
                padded_key = encoded_key + "=" * (-len(encoded_key) % 4)
                public_key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(padded_key))
                Ed25519Verifier(public_key, "management-reconciler").verify(receipt, signature)
            except (ManagedSecurityError, ValueError, binascii.Error) as exc:
                raise ManagementDenied("receipt signature is invalid") from exc
            receipt_digest = managed_digest(receipt)
            cursor.execute(
                """
                INSERT INTO management_operation_receipts
                  (operation_id, deployment_id, tenant_id, fencing_token, command_id,
                   manifest_digest, plan_hash, observed_generation,
                   resource_inventory, verification_summary, provider_update_id,
                   receipt_digest, receipt_signature, completed_at)
                VALUES (CAST(%(operation)s AS uuid), %(deployment)s, %(tenant)s, %(fence)s, CAST(%(command)s AS uuid),
                        %(manifest)s, %(plan)s, %(generation)s,
                        CAST(%(inventory)s AS jsonb), CAST(%(verification)s AS jsonb),
                        %(provider_update)s, %(receipt_digest)s, %(signature)s, %(completed)s)
                """,
                {
                    "operation": operation_id,
                    "deployment": receipt["deployment_id"],
                    "tenant": receipt["tenant_id"],
                    "fence": receipt["fencing_token"],
                    "command": receipt["command_id"],
                    "manifest": receipt["manifest_digest"],
                    "plan": receipt["plan_hash"],
                    "generation": receipt["observed_generation"],
                    "inventory": json.dumps(receipt["resource_inventory"], separators=(",", ":")),
                    "verification": json.dumps(receipt["verification_summary"], separators=(",", ":")),
                    "provider_update": receipt.get("provider_update_id"),
                    "receipt_digest": receipt_digest,
                    "signature": signature,
                    "completed": receipt["completed_at"],
                },
            )
            cursor.execute(
                """
                UPDATE management_operations
                   SET status = 'succeeded', claimed_by = NULL, claimed_phase = NULL,
                       claim_command_id = NULL, claimed_at = NULL, lease_expires_at = NULL, updated_at = now()
                 WHERE operation_id = CAST(%s AS uuid)
                """,
                (operation_id,),
            )
            cursor.execute(
                """
                UPDATE management_deployments
                   SET observed_generation = %(generation)s,
                       observed_manifest_digest = %(digest)s,
                       state = 'active', updated_at = now()
                 WHERE deployment_id = %(deployment)s
                   AND next_fencing_token = %(next_fence)s
                 RETURNING *
                """,
                {
                    "generation": row["target_generation"],
                    "digest": row["manifest_digest"],
                    "deployment": row["deployment_id"],
                    "next_fence": int(row["fencing_token"]) + 1,
                },
            )
            deployment = cursor.fetchone()
            if deployment is None:
                raise ManagementConflict("deployment fence advanced before receipt commit")
            cursor.execute(
                """
                INSERT INTO management_operation_events (operation_id, sequence, event_type, payload)
                SELECT CAST(%(operation)s AS uuid), COALESCE(max(sequence), 0) + 1,
                       'operation.succeeded', CAST(%(payload)s AS jsonb)
                  FROM management_operation_events WHERE operation_id = CAST(%(operation)s AS uuid);
                INSERT INTO management_outbox (aggregate_id, event_type, payload)
                VALUES (CAST(%(operation)s AS uuid), 'management.operation.succeeded', CAST(%(payload)s AS jsonb))
                """,
                {
                    "operation": operation_id,
                    "payload": json.dumps({"command_id": receipt["command_id"], "receipt_digest": receipt_digest}),
                },
            )
            return dict(deployment)

    def fail_operation(
        self,
        operation_id: str,
        workload_spiffe_id: str,
        runner_id: str,
        command_id: str,
        fencing_token: int,
        phase: str,
        error_code: str,
        error_detail: str,
    ) -> dict[str, Any]:
        with self._transaction() as cursor:
            cursor.execute(
                """
                SELECT o.*, b.reconciler_spiffe_id
                  FROM management_operations o
                  JOIN management_deployments d USING (deployment_id)
                  JOIN management_account_bindings b ON b.binding_ref = d.binding_ref
                 WHERE o.operation_id = CAST(%s AS uuid)
                 FOR UPDATE OF o, d
                """,
                (operation_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise ManagementError("operation was not found")
            if row["reconciler_spiffe_id"] != workload_spiffe_id or row["claimed_by"] != runner_id:
                raise ManagementDenied("failure is not from the current bound claimant")
            if str(row["claim_command_id"]) != command_id:
                raise ManagementConflict("failure command is stale")
            if row["status"] != "claimed" or row["claimed_phase"] != phase or int(row["fencing_token"]) != fencing_token:
                raise ManagementConflict("failure claimant is stale")
            cursor.execute(
                """
                UPDATE management_operations
                   SET status = 'recovery_required', claimed_by = NULL,
                       claimed_at = NULL, lease_expires_at = NULL,
                       last_error_code = %(code)s, last_error_detail = %(detail)s, updated_at = now()
                 WHERE operation_id = CAST(%(operation)s AS uuid)
                 RETURNING *
                """,
                {"operation": operation_id, "code": error_code, "detail": error_detail},
            )
            failed = dict(cursor.fetchone())
            cursor.execute(
                "UPDATE management_deployments SET state = 'recovery_required', updated_at = now() WHERE deployment_id = %s",
                (failed["deployment_id"],),
            )
            payload = json.dumps(
                {"command_id": command_id, "phase": phase, "error_code": error_code}, separators=(",", ":")
            )
            cursor.execute(
                """
                INSERT INTO management_operation_events (operation_id, sequence, event_type, payload)
                SELECT CAST(%(operation)s AS uuid), COALESCE(max(sequence), 0) + 1,
                       'operation.recovery_required', CAST(%(payload)s AS jsonb)
                  FROM management_operation_events WHERE operation_id = CAST(%(operation)s AS uuid);
                INSERT INTO management_outbox (aggregate_id, event_type, payload)
                VALUES (CAST(%(operation)s AS uuid), 'management.operation.recovery_required', CAST(%(payload)s AS jsonb))
                """,
                {"operation": operation_id, "payload": payload},
            )
            return failed

    def cancel_operation(self, operation_id: str, actor: OperatorIdentity) -> dict[str, Any]:
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT * FROM management_operations WHERE operation_id = CAST(%s AS uuid) FOR UPDATE",
                (operation_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise ManagementError("operation was not found")
            self._scope(cursor, actor, str(row["tenant_id"]), ("platform_admin", "deployment_operator"))
            if row["status"] in ("succeeded", "failed", "cancelled"):
                raise ManagementConflict("operation is already terminal")
            cursor.execute(
                """
                UPDATE management_deployments
                   SET next_fencing_token = next_fencing_token + 1,
                       desired_generation = observed_generation,
                       desired_manifest = NULL,
                       desired_manifest_digest = observed_manifest_digest,
                       state = 'recovery_required', updated_at = now()
                 WHERE deployment_id = %(deployment)s
                """,
                {"deployment": row["deployment_id"]},
            )
            cursor.execute(
                """
                UPDATE management_operations
                   SET status = 'cancelled', claimed_by = NULL, claimed_phase = NULL,
                       claim_command_id = NULL, claimed_at = NULL, lease_expires_at = NULL, updated_at = now()
                 WHERE operation_id = CAST(%(operation)s AS uuid)
                 RETURNING *
                """,
                {"operation": operation_id},
            )
            cancelled = dict(cursor.fetchone())
            payload = json.dumps({"fenced_token": row["fencing_token"]}, separators=(",", ":"))
            cursor.execute(
                """
                INSERT INTO management_operation_events (operation_id, sequence, event_type, payload)
                SELECT CAST(%(operation)s AS uuid), COALESCE(max(sequence), 0) + 1,
                       'operation.cancelled', CAST(%(payload)s AS jsonb)
                  FROM management_operation_events WHERE operation_id = CAST(%(operation)s AS uuid);
                INSERT INTO management_outbox (aggregate_id, event_type, payload)
                VALUES (CAST(%(operation)s AS uuid), 'management.operation.cancelled', CAST(%(payload)s AS jsonb))
                """,
                {"operation": operation_id, "payload": payload},
            )
            return cancelled
