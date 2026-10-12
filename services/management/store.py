from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

import psycopg2
from core.agents.managed_execution import (
    Ed25519Verifier,
    ManagedSecurityError,
    managed_digest,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from psycopg2.extras import RealDictCursor
from services.management.auth import OperatorIdentity
from services.management.byoc import enrollment_proof
from services.management.contracts import (
    BYOCEnrollmentRequest,
    BYOCHealthEvent,
    DeploymentManifest,
)
from services.management.saas_auth import CustomerIdentity


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
                raise ManagementUnavailable(
                    "management database readiness check failed"
                )

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
    def _scope(
        cursor, actor: OperatorIdentity, tenant_id: str, roles: tuple[str, ...]
    ) -> None:
        cursor.execute(
            """
            SELECT 1
              FROM management_operator_scopes
             WHERE issuer = %(issuer)s AND subject_id = %(subject)s
               AND status = 'active' AND role = ANY(%(roles)s)
               AND (tenant_id = %(tenant)s OR tenant_id IS NULL)
             LIMIT 1
            """,
            {
                "issuer": actor.issuer,
                "subject": actor.subject_id,
                "tenant": tenant_id,
                "roles": list(roles),
            },
        )
        if cursor.fetchone() is None:
            raise ManagementDenied(
                "operator is not authorized for this tenant operation"
            )

    @staticmethod
    def _binding(cursor, manifest: DeploymentManifest) -> dict[str, Any]:
        cursor.execute(
            """
            SELECT * FROM management_account_bindings
             WHERE binding_ref = %(binding)s AND tenant_id = %(tenant)s
               AND deployment_id = %(deployment)s AND provider = 'aws'
               AND (
                 (execution_profile = 'aws'
                  AND account_id = substring(role_arn from 'arn:aws:iam::([0-9]{12}):role/'))
                 OR
                 (execution_profile = 'localstack'
                  AND account_id = '000000000000' AND role_arn = '')
                 OR
                 (execution_profile IN ('byoc', 'byoc-localstack')
                  AND account_id ~ '^[0-9]{12}$' AND role_arn = '')
               )
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
        held = dict(row)
        if (manifest.mode == "byoc") != (
            held["execution_profile"] in {"byoc", "byoc-localstack"}
        ):
            raise ManagementDenied("deployment mode does not match the trusted binding")
        return held

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
        held = {
            str(row["digest_ref"]): str(row["artifact_kind"])
            for row in cursor.fetchall()
        }
        if held != required:
            raise ManagementDenied(
                "manifest contains an unapproved or incorrectly classified artifact"
            )

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
            self._scope(
                cursor,
                actor,
                manifest.tenant_id,
                ("platform_admin", "deployment_operator"),
            )
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
                if (
                    existing["manifest_digest"] != digest
                    or existing["operation_kind"] != operation_kind
                ):
                    raise ManagementConflict(
                        "idempotency key was already used for different work"
                    )
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
                    raise ManagementConflict(
                        "unregistered deployment requires generation-zero provision"
                    )
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
                raise ManagementDenied(
                    "manifest identity does not match the registered deployment"
                )
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
            manifest_json = json.dumps(
                manifest.model_dump(mode="json"), separators=(",", ":"), sort_keys=True
            )
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
            event = {
                "manifest_digest": digest,
                "target_generation": manifest.generation,
                "fencing_token": fence,
            }
            cursor.execute(
                """
                INSERT INTO management_operation_events (operation_id, sequence, event_type, payload)
                VALUES (CAST(%(operation)s AS uuid), 1, 'operation.requested', CAST(%(payload)s AS jsonb));
                INSERT INTO management_outbox (aggregate_id, event_type, payload)
                VALUES (CAST(%(operation)s AS uuid), 'management.operation.plan_requested', CAST(%(payload)s AS jsonb))
                """,
                {
                    "operation": str(operation_id),
                    "payload": json.dumps(event, separators=(",", ":")),
                },
            )
            return operation

    def get_operation(
        self, operation_id: str, actor: OperatorIdentity
    ) -> dict[str, Any] | None:
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT * FROM management_operations WHERE operation_id = CAST(%s AS uuid)",
                (operation_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            self._scope(
                cursor,
                actor,
                str(row["tenant_id"]),
                (
                    "platform_admin",
                    "deployment_operator",
                    "deployment_approver",
                    "auditor",
                ),
            )
            return dict(row)

    def get_deployment(
        self, deployment_id: str, actor: OperatorIdentity
    ) -> dict[str, Any] | None:
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT * FROM management_deployments WHERE deployment_id = %s",
                (deployment_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            self._scope(
                cursor,
                actor,
                str(row["tenant_id"]),
                (
                    "platform_admin",
                    "deployment_operator",
                    "deployment_approver",
                    "auditor",
                ),
            )
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
            self._scope(
                cursor,
                actor,
                str(operation["tenant_id"]),
                ("platform_admin", "deployment_approver"),
            )
            if (
                operation["actor_issuer"] == actor.issuer
                and operation["actor_subject"] == actor.subject_id
            ):
                raise ManagementDenied(
                    "deployment requester cannot approve the same operation"
                )
            if operation["status"] != "awaiting_approval":
                raise ManagementConflict("operation is not awaiting approval")
            if (
                operation["manifest_digest"] != manifest_digest_value
                or operation["plan_hash"] != plan_hash
            ):
                raise ManagementConflict(
                    "approval does not match the current manifest and plan"
                )
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
                    "payload": json.dumps(
                        {
                            "approver_issuer": actor.issuer,
                            "approver_subject": actor.subject_id,
                            "plan_hash": plan_hash,
                        }
                    ),
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
                raise ManagementDenied(
                    "reconciler workload is not bound to this deployment"
                )
            if int(row["fencing_token"]) != int(row["next_fencing_token"]) - 1:
                raise ManagementConflict(
                    "operation was fenced by newer deployment work"
                )
            if row["manifest_digest"] != row["desired_manifest_digest"]:
                raise ManagementConflict(
                    "desired manifest changed after operation admission"
                )
            expected_status = "planning" if phase == "plan" else "approved"
            reclaimable = (
                row["status"] == "claimed"
                and row["claimed_phase"] == phase
                and row["lease_expires_at"] is not None
                and row["lease_expires_at"] <= datetime.now(timezone.utc)
            )
            retryable = (
                row["status"] == "recovery_required" and row["claimed_phase"] == phase
            )
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
                {
                    "operation": operation_id,
                    "runner": runner_id,
                    "phase": phase,
                    "command": str(command_id),
                },
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
            if (
                row["reconciler_spiffe_id"] != workload_spiffe_id
                or row["claimed_by"] != runner_id
            ):
                raise ManagementDenied(
                    "plan result is not from the current bound claimant"
                )
            if str(row["claim_command_id"]) != command_id:
                raise ManagementConflict("plan command is stale")
            if (
                row["status"] != "claimed"
                or row["claimed_phase"] != "plan"
                or int(row["fencing_token"]) != fencing_token
            ):
                raise ManagementConflict("plan claimant is stale")
            if row["lease_expires_at"] is None or row[
                "lease_expires_at"
            ] <= datetime.now(timezone.utc):
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
                {
                    "command_id": command_id,
                    "manifest_digest": digest,
                    "plan_hash": plan_hash,
                },
                separators=(",", ":"),
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
            if (
                row["reconciler_spiffe_id"] != workload_spiffe_id
                or row["claimed_by"] != runner_id
            ):
                raise ManagementDenied("receipt is not from the current bound claimant")
            if (
                row["status"] != "claimed"
                or row["claimed_phase"] != "apply"
                or int(row["next_fencing_token"]) - 1 != int(row["fencing_token"])
            ):
                raise ManagementConflict("receipt claimant is stale")
            if row["lease_expires_at"] is None or row[
                "lease_expires_at"
            ] <= datetime.now(timezone.utc):
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
                public_key = Ed25519PublicKey.from_public_bytes(
                    base64.urlsafe_b64decode(padded_key)
                )
                Ed25519Verifier(public_key, "management-reconciler").verify(
                    receipt, signature
                )
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
                    "inventory": json.dumps(
                        receipt["resource_inventory"], separators=(",", ":")
                    ),
                    "verification": json.dumps(
                        receipt["verification_summary"], separators=(",", ":")
                    ),
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
                raise ManagementConflict(
                    "deployment fence advanced before receipt commit"
                )
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
                    "payload": json.dumps(
                        {
                            "command_id": receipt["command_id"],
                            "receipt_digest": receipt_digest,
                        }
                    ),
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
            if (
                row["reconciler_spiffe_id"] != workload_spiffe_id
                or row["claimed_by"] != runner_id
            ):
                raise ManagementDenied("failure is not from the current bound claimant")
            if str(row["claim_command_id"]) != command_id:
                raise ManagementConflict("failure command is stale")
            if (
                row["status"] != "claimed"
                or row["claimed_phase"] != phase
                or int(row["fencing_token"]) != fencing_token
            ):
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
                {"command_id": command_id, "phase": phase, "error_code": error_code},
                separators=(",", ":"),
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

    def cancel_operation(
        self, operation_id: str, actor: OperatorIdentity
    ) -> dict[str, Any]:
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT * FROM management_operations WHERE operation_id = CAST(%s AS uuid) FOR UPDATE",
                (operation_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise ManagementError("operation was not found")
            self._scope(
                cursor,
                actor,
                str(row["tenant_id"]),
                ("platform_admin", "deployment_operator"),
            )
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
            payload = json.dumps(
                {"fenced_token": row["fencing_token"]}, separators=(",", ":")
            )
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

    def list_saas_contexts(self, actor: CustomerIdentity) -> list[dict[str, Any]]:
        """Return only active tenant contexts derived from durable membership."""
        with self._transaction() as cursor:
            cursor.execute(
                """
                SELECT m.tenant_id, ot.organization_id, t.display_name,
                       array_agg(m.role ORDER BY m.role) AS roles,
                       min(m.membership_version) AS min_membership_version,
                       max(m.membership_version) AS membership_version,
                       b.deployment_id, b.cell_id, c.region
                  FROM management_tenant_memberships m
                  JOIN management_tenants t ON t.tenant_id = m.tenant_id
                  JOIN management_organization_tenants ot ON ot.tenant_id = m.tenant_id
                  JOIN management_organizations o ON o.organization_id = ot.organization_id
                  JOIN management_saas_tenant_bindings b ON b.tenant_id = m.tenant_id
                  JOIN management_saas_cells c ON c.cell_id = b.cell_id
                  JOIN management_deployments d
                    ON d.tenant_id = b.tenant_id AND d.deployment_id = b.deployment_id
                 WHERE m.issuer = %(issuer)s AND m.subject_id = %(subject)s
                   AND m.status = 'active' AND t.status = 'active' AND o.status = 'active'
                   AND b.status = 'active' AND c.status = 'active' AND d.state = 'active'
                 GROUP BY m.tenant_id, ot.organization_id, t.display_name,
                          b.deployment_id, b.cell_id, c.region
                 ORDER BY m.tenant_id
                """,
                {"issuer": actor.issuer, "subject": actor.subject_id},
            )
            contexts = []
            for value in cursor.fetchall():
                row = dict(value)
                if int(row.pop("min_membership_version")) != int(
                    row["membership_version"]
                ):
                    continue
                contexts.append(row)
            return contexts

    def resolve_saas_route(
        self, tenant_id: str, actor: CustomerIdentity
    ) -> dict[str, Any]:
        """Resolve a caller-selected tenant only after membership and route checks."""
        with self._transaction() as cursor:
            cursor.execute(
                """
                SELECT m.tenant_id, min(m.membership_version) AS min_membership_version,
                       max(m.membership_version) AS membership_version,
                       b.deployment_id, b.cell_id, b.route_epoch, c.route_ref, c.region,
                       d.incarnation
                  FROM management_tenant_memberships m
                  JOIN management_tenants t ON t.tenant_id = m.tenant_id
                  JOIN management_saas_tenant_bindings b ON b.tenant_id = m.tenant_id
                  JOIN management_saas_cells c ON c.cell_id = b.cell_id
                  JOIN management_deployments d
                    ON d.tenant_id = b.tenant_id AND d.deployment_id = b.deployment_id
                 WHERE m.issuer = %(issuer)s AND m.subject_id = %(subject)s
                   AND m.tenant_id = %(tenant)s AND m.status = 'active'
                   AND t.status = 'active' AND b.status = 'active'
                   AND c.status = 'active' AND d.state = 'active'
                 GROUP BY m.tenant_id, b.deployment_id, b.cell_id, b.route_epoch,
                          c.route_ref, c.region, d.incarnation
                """,
                {
                    "issuer": actor.issuer,
                    "subject": actor.subject_id,
                    "tenant": tenant_id,
                },
            )
            row = cursor.fetchone()
            if row is None or int(row["min_membership_version"]) != int(
                row["membership_version"]
            ):
                raise ManagementDenied("tenant route is not authorized")
            held = dict(row)
            held.pop("min_membership_version")
            return held

    def record_route_ticket(
        self,
        ticket_id: str,
        route: dict[str, Any],
        actor: CustomerIdentity,
        expires_at: datetime,
    ) -> None:
        with self._transaction() as cursor:
            # Recheck mutable authority in the same transaction as the audit record.
            cursor.execute(
                """
                SELECT min(m.membership_version) AS min_membership_version,
                       max(m.membership_version) AS max_membership_version,
                       b.deployment_id, b.cell_id, b.route_epoch
                  FROM management_tenant_memberships m
                  JOIN management_saas_tenant_bindings b ON b.tenant_id = m.tenant_id
                 WHERE m.issuer = %(issuer)s AND m.subject_id = %(subject)s
                   AND m.tenant_id = %(tenant)s AND m.status = 'active'
                   AND b.status = 'active'
                 GROUP BY b.deployment_id, b.cell_id, b.route_epoch
                """,
                {
                    "issuer": actor.issuer,
                    "subject": actor.subject_id,
                    "tenant": route["tenant_id"],
                    "membership": route["membership_version"],
                    "deployment": route["deployment_id"],
                    "cell": route["cell_id"],
                    "epoch": route["route_epoch"],
                },
            )
            current = cursor.fetchone()
            if (
                current is None
                or int(current["min_membership_version"])
                != int(route["membership_version"])
                or int(current["max_membership_version"])
                != int(route["membership_version"])
                or current["deployment_id"] != route["deployment_id"]
                or current["cell_id"] != route["cell_id"]
                or int(current["route_epoch"]) != int(route["route_epoch"])
            ):
                raise ManagementDenied("tenant route changed before ticket issue")
            cursor.execute(
                """
                INSERT INTO management_route_ticket_audit
                  (ticket_id, issuer, subject_id, tenant_id, deployment_id, cell_id,
                   membership_version, route_epoch, expires_at)
                VALUES (CAST(%(ticket)s AS uuid), %(issuer)s, %(subject)s, %(tenant)s,
                        %(deployment)s, %(cell)s, %(membership)s, %(epoch)s, %(expires)s)
                """,
                {
                    "ticket": ticket_id,
                    "issuer": actor.issuer,
                    "subject": actor.subject_id,
                    "tenant": route["tenant_id"],
                    "deployment": route["deployment_id"],
                    "cell": route["cell_id"],
                    "membership": route["membership_version"],
                    "epoch": route["route_epoch"],
                    "expires": expires_at,
                },
            )
            cursor.execute(
                """
                INSERT INTO management_saas_audit
                  (tenant_id, actor_kind, actor_id, action, outcome, reason_code, resource_ref)
                VALUES (%s, 'user', %s, 'route.issue', 'allowed', 'active_membership', %s)
                """,
                (
                    route["tenant_id"],
                    f"{actor.issuer}#{actor.subject_id}",
                    route["deployment_id"],
                ),
            )

    @staticmethod
    def _saas_workload(
        cursor, deployment_id: str, workload_spiffe_id: str
    ) -> dict[str, Any]:
        cursor.execute(
            """
            SELECT b.tenant_id, b.deployment_id
              FROM management_saas_tenant_bindings b
              JOIN management_tenants t ON t.tenant_id = b.tenant_id
              JOIN management_deployments d
                ON d.tenant_id = b.tenant_id AND d.deployment_id = b.deployment_id
             WHERE b.deployment_id = %(deployment)s
               AND b.data_plane_spiffe_id = %(spiffe)s
               AND b.status = 'active' AND t.status = 'active' AND d.state = 'active'
             FOR SHARE OF b, d
            """,
            {"deployment": deployment_id, "spiffe": workload_spiffe_id},
        )
        row = cursor.fetchone()
        if row is None:
            raise ManagementDenied(
                "workload is not bound to the active tenant deployment"
            )
        return dict(row)

    def reserve_quota(
        self,
        deployment_id: str,
        workload_spiffe_id: str,
        invocation_id: str,
        request_digest: str,
        dimension: str,
        amount: int,
    ) -> dict[str, Any]:
        if amount <= 0:
            raise ManagementError("quota reservation amount must be positive")
        with self._transaction() as cursor:
            workload = self._saas_workload(cursor, deployment_id, workload_spiffe_id)
            tenant_id = str(workload["tenant_id"])
            cursor.execute(
                """
                SELECT * FROM management_usage_reservations
                 WHERE tenant_id = %s AND invocation_id = %s
                 FOR UPDATE
                """,
                (tenant_id, invocation_id),
            )
            existing = cursor.fetchone()
            if existing is not None:
                if (
                    existing["request_digest"] != request_digest
                    or existing["dimension"] != dimension
                    or int(existing["reserved_amount"]) != amount
                ):
                    raise ManagementConflict(
                        "quota invocation id was reused with different content"
                    )
                return dict(existing)
            cursor.execute(
                """
                SELECT * FROM management_quota_policies
                 WHERE tenant_id = %s AND dimension = %s AND status = 'active'
                 FOR UPDATE
                """,
                (tenant_id, dimension),
            )
            policy = cursor.fetchone()
            if policy is None:
                raise ManagementDenied("quota policy is unavailable")
            now = datetime.now(timezone.utc)
            seconds = int(policy["window_seconds"])
            window = datetime.fromtimestamp(
                int(now.timestamp()) // seconds * seconds, timezone.utc
            )
            cursor.execute(
                """
                INSERT INTO management_usage_windows
                  (tenant_id, dimension, window_started_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (tenant_id, dimension, window_started_at) DO NOTHING
                """,
                (tenant_id, dimension, window),
            )
            cursor.execute(
                """
                SELECT * FROM management_usage_windows
                 WHERE tenant_id = %s AND dimension = %s AND window_started_at = %s
                 FOR UPDATE
                """,
                (tenant_id, dimension, window),
            )
            usage = cursor.fetchone()
            assert usage is not None
            cursor.execute(
                """
                SELECT reserved_amount FROM management_usage_reservations
                 WHERE tenant_id = %s AND dimension = %s AND window_started_at = %s
                   AND status = 'reserved' AND expires_at <= %s
                 FOR UPDATE
                """,
                (tenant_id, dimension, window, now),
            )
            expired_amount = sum(
                int(row["reserved_amount"]) for row in cursor.fetchall()
            )
            if expired_amount:
                cursor.execute(
                    """
                    UPDATE management_usage_reservations
                       SET status = 'released', updated_at = now()
                     WHERE tenant_id = %(tenant)s AND dimension = %(dimension)s
                       AND window_started_at = %(window)s AND status = 'reserved'
                       AND expires_at <= %(now)s;
                    UPDATE management_usage_windows
                       SET reserved_amount = reserved_amount - %(expired)s, updated_at = now()
                     WHERE tenant_id = %(tenant)s AND dimension = %(dimension)s
                       AND window_started_at = %(window)s
                     RETURNING *
                    """,
                    {
                        "tenant": tenant_id,
                        "dimension": dimension,
                        "window": window,
                        "now": now,
                        "expired": expired_amount,
                    },
                )
                usage = cursor.fetchone()
                assert usage is not None
            if int(usage["reserved_amount"]) + int(
                usage["committed_amount"]
            ) + amount > int(policy["hard_limit"]):
                raise ManagementDenied("tenant quota is exhausted")
            reservation_id = str(uuid.uuid4())
            expiry = now + timedelta(minutes=5)
            cursor.execute(
                """
                UPDATE management_usage_windows
                   SET reserved_amount = reserved_amount + %(amount)s, updated_at = now()
                 WHERE tenant_id = %(tenant)s AND dimension = %(dimension)s
                   AND window_started_at = %(window)s;
                INSERT INTO management_usage_reservations
                  (reservation_id, tenant_id, deployment_id, dimension, invocation_id,
                   request_digest, reserved_amount, policy_version, window_started_at, expires_at)
                VALUES (CAST(%(reservation)s AS uuid), %(tenant)s, %(deployment)s, %(dimension)s,
                        %(invocation)s, %(digest)s, %(amount)s, %(version)s, %(window)s, %(expiry)s)
                RETURNING *
                """,
                {
                    "reservation": reservation_id,
                    "tenant": tenant_id,
                    "deployment": deployment_id,
                    "dimension": dimension,
                    "invocation": invocation_id,
                    "digest": request_digest,
                    "amount": amount,
                    "version": policy["policy_version"],
                    "window": window,
                    "expiry": expiry,
                },
            )
            reservation = dict(cursor.fetchone())
            cursor.execute(
                """
                INSERT INTO management_saas_audit
                  (tenant_id, actor_kind, actor_id, action, outcome, reason_code, resource_ref)
                VALUES (%s, 'workload', %s, 'quota.reserve', 'allowed', 'within_hard_limit', %s)
                """,
                (tenant_id, workload_spiffe_id, f"{dimension}:{reservation_id}"),
            )
            return reservation

    def commit_quota(
        self,
        deployment_id: str,
        workload_spiffe_id: str,
        reservation_id: str,
        request_digest: str,
        actual_amount: int,
    ) -> dict[str, Any]:
        if actual_amount < 0:
            raise ManagementError("actual quota usage cannot be negative")
        with self._transaction() as cursor:
            workload = self._saas_workload(cursor, deployment_id, workload_spiffe_id)
            cursor.execute(
                """
                SELECT * FROM management_usage_reservations
                 WHERE reservation_id = CAST(%s AS uuid) AND tenant_id = %s AND deployment_id = %s
                 FOR UPDATE
                """,
                (reservation_id, workload["tenant_id"], deployment_id),
            )
            row = cursor.fetchone()
            if row is None or row["request_digest"] != request_digest:
                raise ManagementDenied(
                    "quota reservation is not authorized for this request"
                )
            if row["status"] == "committed":
                if int(row["committed_amount"]) != actual_amount:
                    raise ManagementConflict(
                        "quota reservation was already committed with different usage"
                    )
                return dict(row)
            if row["status"] != "reserved" or row["expires_at"] <= datetime.now(
                timezone.utc
            ):
                raise ManagementConflict("quota reservation is no longer active")
            if actual_amount > int(row["reserved_amount"]):
                raise ManagementDenied("actual usage exceeds the reserved quota")
            cursor.execute(
                """
                UPDATE management_usage_windows
                   SET reserved_amount = reserved_amount - %(reserved)s,
                       committed_amount = committed_amount + %(actual)s,
                       updated_at = now()
                 WHERE tenant_id = %(tenant)s AND dimension = %(dimension)s
                   AND window_started_at = %(window)s;
                UPDATE management_usage_reservations
                   SET status = 'committed', committed_amount = %(actual)s, updated_at = now()
                 WHERE reservation_id = CAST(%(reservation)s AS uuid)
                 RETURNING *
                """,
                {
                    "reserved": row["reserved_amount"],
                    "actual": actual_amount,
                    "tenant": row["tenant_id"],
                    "dimension": row["dimension"],
                    "window": row["window_started_at"],
                    "reservation": reservation_id,
                },
            )
            committed = dict(cursor.fetchone())
            cursor.execute(
                """
                INSERT INTO management_saas_audit
                  (tenant_id, actor_kind, actor_id, action, outcome, reason_code, resource_ref)
                VALUES (%s, 'workload', %s, 'quota.commit', 'allowed', 'reservation_reconciled', %s)
                """,
                (
                    row["tenant_id"],
                    workload_spiffe_id,
                    f"{row['dimension']}:{reservation_id}",
                ),
            )
            return committed

    def list_usage(
        self, tenant_id: str, actor: CustomerIdentity
    ) -> list[dict[str, Any]]:
        with self._transaction() as cursor:
            cursor.execute(
                """
                SELECT 1 FROM management_tenant_memberships
                 WHERE issuer = %s AND subject_id = %s AND tenant_id = %s
                   AND status = 'active' LIMIT 1
                """,
                (actor.issuer, actor.subject_id, tenant_id),
            )
            if cursor.fetchone() is None:
                raise ManagementDenied("tenant usage is not authorized")
            cursor.execute(
                """
                SELECT w.tenant_id, w.dimension, w.window_started_at,
                       w.reserved_amount, w.committed_amount,
                       p.hard_limit, p.policy_version
                  FROM management_usage_windows w
                  JOIN management_quota_policies p
                    ON p.tenant_id = w.tenant_id AND p.dimension = w.dimension
                 WHERE w.tenant_id = %s
                 ORDER BY w.dimension, w.window_started_at DESC
                """,
                (tenant_id,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def create_byoc_enrollment(
        self,
        request: BYOCEnrollmentRequest,
        actor: OperatorIdentity,
        enrollment_id: str,
        token_digest: str,
    ) -> dict[str, Any]:
        expires_at = request.expires_at.astimezone(timezone.utc)
        now = datetime.now(timezone.utc)
        if expires_at <= now or expires_at > now + timedelta(minutes=15):
            raise ManagementError("BYOC enrollment must expire within 15 minutes")
        with self._transaction() as cursor:
            self._scope(
                cursor,
                actor,
                request.tenant_id,
                ("platform_admin", "deployment_operator"),
            )
            cursor.execute(
                """
                SELECT b.*, d.state
                  FROM management_account_bindings b
                  JOIN management_deployments d
                    ON d.tenant_id = b.tenant_id AND d.deployment_id = b.deployment_id
                 WHERE b.tenant_id = %(tenant)s AND b.deployment_id = %(deployment)s
                   AND b.account_id = %(account)s
                   AND b.execution_profile IN ('byoc', 'byoc-localstack')
                   AND b.reconciler_spiffe_id = %(spiffe)s
                   AND b.role_arn = '' AND b.status = 'active'
                   AND d.state NOT IN ('offboarding', 'retention_pending', 'deleted')
                 FOR SHARE OF b, d
                """,
                {
                    "tenant": request.tenant_id,
                    "deployment": request.deployment_id,
                    "account": request.account_id,
                    "spiffe": request.connector_spiffe_id,
                },
            )
            if cursor.fetchone() is None:
                raise ManagementDenied(
                    "BYOC enrollment target is not an active trusted binding"
                )
            cursor.execute(
                """
                SELECT * FROM management_byoc_enrollments
                 WHERE deployment_id = %s AND idempotency_key = %s
                 FOR UPDATE
                """,
                (request.deployment_id, request.idempotency_key),
            )
            existing = cursor.fetchone()
            if existing is not None:
                if (
                    str(existing["enrollment_id"]) != enrollment_id
                    or existing["token_digest"] != token_digest
                    or existing["account_id"] != request.account_id
                    or existing["connector_spiffe_id"] != request.connector_spiffe_id
                    or existing["local_policy_digest"] != request.local_policy_digest
                    or existing["expires_at"] != expires_at
                ):
                    raise ManagementConflict(
                        "BYOC enrollment idempotency key was reused"
                    )
                if existing["status"] != "pending" or existing["expires_at"] <= now:
                    raise ManagementConflict("BYOC enrollment is no longer active")
                return dict(existing)
            cursor.execute(
                """
                INSERT INTO management_byoc_enrollments
                  (enrollment_id, tenant_id, deployment_id, account_id, connector_spiffe_id,
                   local_policy_digest, token_digest, idempotency_key,
                   requested_by_issuer, requested_by_subject, expires_at)
                VALUES (CAST(%(enrollment)s AS uuid), %(tenant)s, %(deployment)s, %(account)s,
                        %(spiffe)s, %(policy)s, %(token)s, %(idempotency)s,
                        %(issuer)s, %(subject)s, %(expires)s)
                RETURNING *
                """,
                {
                    "enrollment": enrollment_id,
                    "tenant": request.tenant_id,
                    "deployment": request.deployment_id,
                    "account": request.account_id,
                    "spiffe": request.connector_spiffe_id,
                    "policy": request.local_policy_digest,
                    "token": token_digest,
                    "idempotency": request.idempotency_key,
                    "issuer": actor.issuer,
                    "subject": actor.subject_id,
                    "expires": expires_at,
                },
            )
            enrolled = dict(cursor.fetchone())
            cursor.execute(
                """
                INSERT INTO management_byoc_audit
                  (tenant_id, deployment_id, actor_kind, actor_id, action, outcome,
                   reason_code, resource_ref)
                VALUES (%s, %s, 'operator', %s, 'enrollment.issue', 'allowed',
                        'trusted_byoc_binding', %s)
                """,
                (
                    request.tenant_id,
                    request.deployment_id,
                    f"{actor.issuer}#{actor.subject_id}",
                    enrollment_id,
                ),
            )
            return enrolled

    def enroll_byoc_connector(
        self,
        enrollment_id: str,
        enrollment_token: str,
        account_id: str,
        local_policy_digest: str,
        connector_public_key: str,
        proof_signature: str,
        workload_spiffe_id: str,
    ) -> dict[str, Any]:
        token_digest = hashlib.sha256(enrollment_token.encode()).hexdigest()
        with self._transaction() as cursor:
            cursor.execute(
                """
                SELECT e.*, b.status AS binding_status, b.execution_profile,
                       d.incarnation, d.state AS deployment_state
                  FROM management_byoc_enrollments e
                  JOIN management_account_bindings b
                    ON b.tenant_id = e.tenant_id AND b.deployment_id = e.deployment_id
                  JOIN management_deployments d
                    ON d.tenant_id = e.tenant_id AND d.deployment_id = e.deployment_id
                 WHERE e.enrollment_id = CAST(%s AS uuid)
                 FOR UPDATE OF e, b, d
                """,
                (enrollment_id,),
            )
            row = cursor.fetchone()
            now = datetime.now(timezone.utc)
            if (
                row is None
                or row["status"] != "pending"
                or row["consumed_at"] is not None
                or row["expires_at"] <= now
                or not hmac_compare(row["token_digest"], token_digest)
                or row["account_id"] != account_id
                or row["connector_spiffe_id"] != workload_spiffe_id
                or row["local_policy_digest"] != local_policy_digest
                or row["binding_status"] != "active"
                or row["execution_profile"] not in {"byoc", "byoc-localstack"}
                or row["deployment_state"]
                in {"offboarding", "retention_pending", "deleted"}
            ):
                raise ManagementDenied("BYOC enrollment is not authorized")
            try:
                padded = connector_public_key + "=" * (-len(connector_public_key) % 4)
                public_raw = base64.urlsafe_b64decode(padded.encode())
                if len(public_raw) != 32:
                    raise ValueError("wrong Ed25519 public key length")
                verifier = Ed25519Verifier(
                    Ed25519PublicKey.from_public_bytes(public_raw), "byoc-enrollment"
                )
                verifier.verify(enrollment_proof(dict(row)), proof_signature)
            except (ValueError, binascii.Error, ManagedSecurityError) as exc:
                raise ManagementDenied("BYOC enrollment proof is invalid") from exc
            cursor.execute(
                """
                INSERT INTO management_byoc_connectors
                  (deployment_id, tenant_id, enrollment_id, account_id, connector_spiffe_id,
                   connector_public_key, local_policy_digest)
                VALUES (%(deployment)s, %(tenant)s, CAST(%(enrollment)s AS uuid), %(account)s,
                        %(spiffe)s, %(public_key)s, %(policy)s)
                ON CONFLICT (deployment_id) DO NOTHING
                RETURNING *
                """,
                {
                    "deployment": row["deployment_id"],
                    "tenant": row["tenant_id"],
                    "enrollment": enrollment_id,
                    "account": account_id,
                    "spiffe": workload_spiffe_id,
                    "public_key": connector_public_key,
                    "policy": local_policy_digest,
                },
            )
            connector = cursor.fetchone()
            if connector is None:
                raise ManagementConflict("BYOC deployment is already enrolled")
            cursor.execute(
                """
                UPDATE management_byoc_enrollments
                   SET status = 'consumed', consumed_at = now()
                 WHERE enrollment_id = CAST(%s AS uuid)
                """,
                (enrollment_id,),
            )
            cursor.execute(
                """
                INSERT INTO management_byoc_audit
                  (tenant_id, deployment_id, actor_kind, actor_id, action, outcome,
                   reason_code, resource_ref)
                VALUES (%s, %s, 'connector', %s, 'connector.enroll', 'allowed',
                        'token_and_key_possession', %s)
                """,
                (
                    row["tenant_id"],
                    row["deployment_id"],
                    workload_spiffe_id,
                    enrollment_id,
                ),
            )
            return dict(connector)

    @staticmethod
    def _byoc_connector(
        cursor, deployment_id: str, workload_spiffe_id: str
    ) -> dict[str, Any]:
        cursor.execute(
            """
            SELECT c.*, d.incarnation, d.state AS deployment_state
              FROM management_byoc_connectors c
              JOIN management_deployments d
                ON d.tenant_id = c.tenant_id AND d.deployment_id = c.deployment_id
             WHERE c.deployment_id = %s AND c.connector_spiffe_id = %s
             FOR UPDATE OF c, d
            """,
            (deployment_id, workload_spiffe_id),
        )
        row = cursor.fetchone()
        if (
            row is None
            or not row["management_enabled"]
            or row["deployment_state"]
            in {"offboarding", "retention_pending", "deleted"}
        ):
            raise ManagementDenied("BYOC connector management access is revoked")
        return dict(row)

    def record_byoc_health(
        self,
        deployment_id: str,
        workload_spiffe_id: str,
        event: BYOCHealthEvent,
    ) -> dict[str, Any]:
        unsigned = event.model_dump(mode="json", exclude={"signature"})
        event_digest = managed_digest(unsigned)
        with self._transaction() as cursor:
            connector = self._byoc_connector(cursor, deployment_id, workload_spiffe_id)
            if str(event.incarnation) != str(
                connector["incarnation"]
            ) or event.revocation_epoch != int(connector["revocation_epoch"]):
                raise ManagementDenied("BYOC health identity is stale")
            try:
                padded = connector["connector_public_key"] + "=" * (
                    -len(connector["connector_public_key"]) % 4
                )
                raw = base64.urlsafe_b64decode(padded.encode())
                verifier = Ed25519Verifier(
                    Ed25519PublicKey.from_public_bytes(raw), "byoc-health"
                )
                verifier.verify(unsigned, event.signature)
            except (ValueError, binascii.Error, ManagedSecurityError) as exc:
                raise ManagementDenied("BYOC health signature is invalid") from exc
            cursor.execute(
                """
                SELECT event_digest FROM management_byoc_health_events
                 WHERE deployment_id = %s AND incarnation = %s AND sequence = %s
                """,
                (deployment_id, str(event.incarnation), event.sequence),
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing["event_digest"] != event_digest:
                    raise ManagementConflict(
                        "BYOC health sequence was reused with different content"
                    )
                return {
                    "deployment_id": deployment_id,
                    "sequence": event.sequence,
                    "event_digest": event_digest,
                    "duplicate": True,
                }
            if event.sequence != int(connector["last_health_sequence"]) + 1:
                raise ManagementConflict("BYOC health sequence is not contiguous")
            occurred_at = event.occurred_at.astimezone(timezone.utc)
            now = datetime.now(timezone.utc)
            if occurred_at > now + timedelta(
                minutes=1
            ) or occurred_at < now - timedelta(days=7):
                raise ManagementDenied(
                    "BYOC health occurrence time is outside the accepted window"
                )
            payload = json.dumps(
                event.payload.model_dump(mode="json"),
                separators=(",", ":"),
                sort_keys=True,
            )
            cursor.execute(
                """
                INSERT INTO management_byoc_health_events
                  (deployment_id, tenant_id, incarnation, sequence, event_kind,
                   event_digest, payload, occurred_at)
                VALUES (%s, %s, %s, %s, %s, %s, CAST(%s AS jsonb), %s);
                UPDATE management_byoc_connectors
                   SET last_health_sequence = %s, last_health_at = now()
                 WHERE deployment_id = %s;
                UPDATE management_deployments
                   SET last_health_at = now(), updated_at = now()
                 WHERE deployment_id = %s
                """,
                (
                    deployment_id,
                    connector["tenant_id"],
                    str(event.incarnation),
                    event.sequence,
                    event.event_kind,
                    event_digest,
                    payload,
                    occurred_at,
                    event.sequence,
                    deployment_id,
                    deployment_id,
                ),
            )
            cursor.execute(
                """
                INSERT INTO management_byoc_audit
                  (tenant_id, deployment_id, actor_kind, actor_id, action, outcome,
                   reason_code, resource_ref)
                VALUES (%s, %s, 'connector', %s, 'health.accept', 'allowed',
                        'signed_contiguous_event', %s)
                """,
                (
                    connector["tenant_id"],
                    deployment_id,
                    workload_spiffe_id,
                    str(event.sequence),
                ),
            )
            return {
                "deployment_id": deployment_id,
                "sequence": event.sequence,
                "event_digest": event_digest,
                "duplicate": False,
            }

    def authorize_byoc_certificate_rotation(
        self, deployment_id: str, workload_spiffe_id: str
    ) -> dict[str, Any]:
        with self._transaction() as cursor:
            connector = self._byoc_connector(cursor, deployment_id, workload_spiffe_id)
            cursor.execute(
                """
                INSERT INTO management_byoc_audit
                  (tenant_id, deployment_id, actor_kind, actor_id, action, outcome,
                   reason_code, resource_ref)
                VALUES (%s, %s, 'connector', %s, 'certificate.rotate', 'allowed',
                        'active_connector_binding', %s)
                """,
                (
                    connector["tenant_id"],
                    deployment_id,
                    workload_spiffe_id,
                    str(connector["trust_version"]),
                ),
            )
            return connector

    def revoke_byoc_management(
        self, tenant_id: str, deployment_id: str, actor: OperatorIdentity
    ) -> dict[str, Any]:
        with self._transaction() as cursor:
            self._scope(
                cursor, actor, tenant_id, ("platform_admin", "deployment_operator")
            )
            cursor.execute(
                """
                UPDATE management_byoc_connectors
                   SET management_enabled = false,
                       revocation_epoch = revocation_epoch + 1,
                       revoked_at = now()
                 WHERE tenant_id = %s AND deployment_id = %s AND management_enabled = true
                RETURNING *
                """,
                (tenant_id, deployment_id),
            )
            connector = cursor.fetchone()
            if connector is None:
                raise ManagementConflict(
                    "BYOC management is already revoked or not enrolled"
                )
            cursor.execute(
                """
                INSERT INTO management_byoc_audit
                  (tenant_id, deployment_id, actor_kind, actor_id, action, outcome,
                   reason_code, resource_ref)
                VALUES (%s, %s, 'operator', %s, 'management.revoke', 'allowed',
                        'operator_revocation', %s)
                """,
                (
                    tenant_id,
                    deployment_id,
                    f"{actor.issuer}#{actor.subject_id}",
                    str(connector["revocation_epoch"]),
                ),
            )
            return dict(connector)


def hmac_compare(left: str, right: str) -> bool:
    """Constant-time compare kept local to avoid treating token digests as identifiers."""
    import hmac

    return hmac.compare_digest(left, right)
