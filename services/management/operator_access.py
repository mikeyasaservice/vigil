from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg2
from core.agents.managed_execution import managed_digest
from psycopg2.extras import RealDictCursor
from services.management.auth import OperatorIdentity
from services.management.contracts import OperatorAccessRequest
from services.management.saas_auth import CustomerIdentity
from services.management.store import (
    ManagementConflict,
    ManagementDenied,
    ManagementUnavailable,
)

SUPPORT_ACTIONS = frozenset(
    {
        "deployment.health.read",
        "diagnostic.bundle.request",
        "audit.read",
        "backup.metadata.read",
    }
)
BREAK_GLASS_ACTIONS = frozenset(
    {
        *SUPPORT_ACTIONS,
        "tenant.data.read",
        "tool.invoke",
        "backup.download",
        "pod.exec",
        "workload.role.change",
    }
)


class OperatorAccessStore:
    """Durable customer-approved operator elevation.

    Authentication proves the workforce subject. This store separately evaluates
    tenant scope, separation of duties, current provisioning state, lease expiry,
    SCIM status, and revocation on every privileged authorization.
    """

    def __init__(self, database_url: str | None = None):
        self.database_url = database_url or os.getenv("MANAGEMENT_DATABASE_URL", "")
        if not self.database_url:
            raise ManagementUnavailable("management database is not configured")

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
        except psycopg2.IntegrityError as exc:
            raise ManagementConflict("operator access state conflicts with durable policy") from exc
        except psycopg2.Error as exc:
            raise ManagementUnavailable("operator access transaction failed") from exc
        finally:
            connection.close()

    @staticmethod
    def _operator_role(
        cursor, actor: OperatorIdentity, tenant_id: str, roles: tuple[str, ...]
    ) -> None:
        cursor.execute(
            """
            SELECT 1 FROM management_operator_scopes
             WHERE issuer = %s AND subject_id = %s AND status = 'active'
               AND role = ANY(%s) AND (tenant_id = %s OR tenant_id IS NULL)
             LIMIT 1
            """,
            (actor.issuer, actor.subject_id, list(roles), tenant_id),
        )
        if cursor.fetchone() is None:
            raise ManagementDenied("operator role is not authorized for this tenant")

    @staticmethod
    def _active_enterprise_user(cursor, actor: OperatorIdentity) -> None:
        if not actor.provider_id:
            raise ManagementDenied("enterprise-federated operator identity is required")
        if not actor.assurance:
            raise ManagementDenied("recent enterprise MFA assurance is required")
        cursor.execute(
            """
            SELECT 1 FROM management_enterprise_users u
            JOIN management_identity_providers p ON p.provider_id = u.provider_id
             WHERE u.provider_id = %s AND u.external_id = %s
               AND u.active AND p.status = 'active'
             LIMIT 1
            """,
            (actor.provider_id, actor.subject_id),
        )
        if cursor.fetchone() is None:
            raise ManagementDenied("enterprise operator identity is inactive")

    @staticmethod
    def _customer_approver(cursor, actor: CustomerIdentity, tenant_id: str) -> None:
        cursor.execute(
            """
            SELECT 1 FROM management_tenant_memberships
             WHERE issuer = %s AND subject_id = %s AND tenant_id = %s
               AND role IN ('tenant_admin', 'approver') AND status = 'active'
             LIMIT 1
            """,
            (actor.issuer, actor.subject_id, tenant_id),
        )
        if cursor.fetchone() is None:
            raise ManagementDenied("customer approver is not authorized for this tenant")

    @staticmethod
    def _audit(
        cursor,
        *,
        tenant_id: str,
        deployment_id: str,
        request_id: str | None,
        session_id: str | None,
        actor_kind: str,
        actor_issuer: str,
        actor_subject: str,
        action: str,
        resource: str,
        outcome: str,
        reason_code: str,
    ) -> None:
        cursor.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (tenant_id,))
        cursor.execute(
            """
            SELECT event_hash FROM management_operator_access_audit
             WHERE tenant_id = %s ORDER BY audit_id DESC LIMIT 1
            """,
            (tenant_id,),
        )
        previous = cursor.fetchone()
        previous_hash = previous["event_hash"] if previous else None
        event_id = str(uuid.uuid4())
        occurred_at = datetime.now(UTC)
        event = {
            "event_id": event_id,
            "tenant_id": tenant_id,
            "deployment_id": deployment_id,
            "request_id": request_id,
            "session_id": session_id,
            "actor_kind": actor_kind,
            "actor_issuer": actor_issuer,
            "actor_subject": actor_subject,
            "action": action,
            "resource_ref": resource,
            "outcome": outcome,
            "reason_code": reason_code,
            "occurred_at": occurred_at.isoformat(),
            "previous_event_hash": previous_hash,
        }
        event_hash = managed_digest(event)
        cursor.execute(
            """
            INSERT INTO management_operator_access_audit
              (event_id, tenant_id, deployment_id, request_id, session_id,
               actor_kind, actor_issuer, actor_subject, action, resource_ref,
               outcome, reason_code, occurred_at, previous_event_hash, event_hash)
            VALUES (%s, %s, %s, CAST(%s AS uuid), CAST(%s AS uuid), %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                event_id,
                tenant_id,
                deployment_id,
                request_id,
                session_id,
                actor_kind,
                actor_issuer,
                actor_subject,
                action,
                resource,
                outcome,
                reason_code,
                occurred_at,
                previous_hash,
                event_hash,
            ),
        )

    def create_request(
        self, body: OperatorAccessRequest, actor: OperatorIdentity
    ) -> dict[str, Any]:
        allowed = SUPPORT_ACTIONS if body.access_kind == "support" else BREAK_GLASS_ACTIONS
        unknown = sorted(set(body.actions) - allowed)
        if unknown:
            raise ManagementDenied(f"operator access action is not recognized: {unknown[0]}")
        canonical = {
            "tenant_id": body.tenant_id,
            "deployment_id": body.deployment_id,
            "access_kind": body.access_kind,
            "actions": sorted(body.actions),
            "resources": sorted(body.resources),
            "justification": body.justification,
            "ticket_ref": body.ticket_ref,
            "incident_ref": body.incident_ref,
            "duration_seconds": body.duration_seconds,
            "requester_issuer": actor.issuer,
            "requester_subject": actor.subject_id,
        }
        digest = managed_digest(canonical)
        request_id = str(uuid.uuid4())
        with self._transaction() as cursor:
            self._active_enterprise_user(cursor, actor)
            self._operator_role(
                cursor, actor, body.tenant_id, ("support_operator", "platform_admin")
            )
            cursor.execute(
                """
                SELECT 1 FROM management_deployments
                 WHERE tenant_id = %s AND deployment_id = %s
                   AND state NOT IN ('offboarding', 'retention_pending', 'deleted')
                 FOR SHARE
                """,
                (body.tenant_id, body.deployment_id),
            )
            if cursor.fetchone() is None:
                raise ManagementDenied("operator access target is not an active deployment")
            cursor.execute(
                """
                INSERT INTO management_operator_access_requests
                  (request_id, tenant_id, deployment_id, access_kind, requested_actions,
                   requested_resources, justification, ticket_ref, incident_ref,
                   requester_issuer, requester_subject, requester_token_id,
                   request_digest, requested_duration_seconds)
                VALUES (CAST(%s AS uuid), %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, request_digest) DO NOTHING
                RETURNING *
                """,
                (
                    request_id,
                    body.tenant_id,
                    body.deployment_id,
                    body.access_kind,
                    sorted(body.actions),
                    sorted(body.resources),
                    body.justification,
                    body.ticket_ref,
                    body.incident_ref,
                    actor.issuer,
                    actor.subject_id,
                    actor.token_id,
                    digest,
                    body.duration_seconds,
                ),
            )
            row = cursor.fetchone()
            if row is None:
                cursor.execute(
                    "SELECT * FROM management_operator_access_requests WHERE tenant_id = %s AND request_digest = %s",
                    (body.tenant_id, digest),
                )
                row = cursor.fetchone()
            held = dict(row)
            self._audit(
                cursor,
                tenant_id=body.tenant_id,
                deployment_id=body.deployment_id,
                request_id=str(held["request_id"]),
                session_id=None,
                actor_kind="operator",
                actor_issuer=actor.issuer,
                actor_subject=actor.subject_id,
                action="operator_access.request",
                resource=body.deployment_id,
                outcome="allowed",
                reason_code="exact_scope_recorded",
            )
            return held

    def customer_approve(
        self, request_id: str, request_digest: str, actor: CustomerIdentity
    ) -> dict[str, Any]:
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT * FROM management_operator_access_requests WHERE request_id = CAST(%s AS uuid) FOR UPDATE",
                (request_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise ManagementDenied("operator access request is unavailable")
            self._customer_approver(cursor, actor, row["tenant_id"])
            if row["request_digest"] != request_digest or row["status"] != "pending_customer":
                raise ManagementConflict("operator access request cannot be customer-approved")
            if (
                row["requester_issuer"] == actor.issuer
                and row["requester_subject"] == actor.subject_id
            ):
                raise ManagementDenied("requester cannot customer-approve their own access")
            cursor.execute(
                """
                UPDATE management_operator_access_requests
                   SET status = 'pending_provider', customer_approved_at = now(),
                       customer_approver_issuer = %s, customer_approver_subject = %s,
                       updated_at = now()
                 WHERE request_id = CAST(%s AS uuid) RETURNING *
                """,
                (actor.issuer, actor.subject_id, request_id),
            )
            approved = dict(cursor.fetchone())
            self._audit(
                cursor,
                tenant_id=row["tenant_id"],
                deployment_id=row["deployment_id"],
                request_id=request_id,
                session_id=None,
                actor_kind="customer",
                actor_issuer=actor.issuer,
                actor_subject=actor.subject_id,
                action="operator_access.customer_approve",
                resource=row["deployment_id"],
                outcome="allowed",
                reason_code="tenant_approver_exact_digest",
            )
            return approved

    def provider_approve(
        self, request_id: str, request_digest: str, actor: OperatorIdentity
    ) -> dict[str, Any]:
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT * FROM management_operator_access_requests WHERE request_id = CAST(%s AS uuid) FOR UPDATE",
                (request_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise ManagementDenied("operator access request is unavailable")
            self._active_enterprise_user(cursor, actor)
            roles = (
                ("break_glass_approver", "platform_admin")
                if row["access_kind"] == "break_glass"
                else ("support_approver", "platform_admin")
            )
            self._operator_role(cursor, actor, row["tenant_id"], roles)
            if row["request_digest"] != request_digest or row["status"] not in {
                "pending_provider",
                "approved",
            }:
                raise ManagementConflict("operator access request cannot be provider-approved")
            if (
                row["requester_issuer"] == actor.issuer
                and row["requester_subject"] == actor.subject_id
            ):
                raise ManagementDenied("requester cannot approve their own access")
            cursor.execute(
                "SELECT count(*) AS count FROM management_operator_access_approvals WHERE request_id = CAST(%s AS uuid)",
                (request_id,),
            )
            count = int(cursor.fetchone()["count"])
            approval_kind = "provider" if count == 0 else "break_glass_corroborator"
            if row["access_kind"] != "break_glass" and count > 0:
                raise ManagementConflict("support access already has provider approval")
            cursor.execute(
                """
                INSERT INTO management_operator_access_approvals
                  (request_id, approval_kind, approver_issuer, approver_subject)
                VALUES (CAST(%s AS uuid), %s, %s, %s)
                """,
                (request_id, approval_kind, actor.issuer, actor.subject_id),
            )
            needed = 2 if row["access_kind"] == "break_glass" else 1
            new_status = "approved" if count + 1 >= needed else "pending_provider"
            cursor.execute(
                "UPDATE management_operator_access_requests SET status = %s, updated_at = now() WHERE request_id = CAST(%s AS uuid) RETURNING *",
                (new_status, request_id),
            )
            approved = dict(cursor.fetchone())
            self._audit(
                cursor,
                tenant_id=row["tenant_id"],
                deployment_id=row["deployment_id"],
                request_id=request_id,
                session_id=None,
                actor_kind="operator",
                actor_issuer=actor.issuer,
                actor_subject=actor.subject_id,
                action="operator_access.provider_approve",
                resource=row["deployment_id"],
                outcome="allowed",
                reason_code=approval_kind,
            )
            return approved

    def activate(self, request_id: str, actor: OperatorIdentity) -> tuple[dict[str, Any], str]:
        token = secrets.token_urlsafe(48)
        token_digest = hashlib.sha256(token.encode()).hexdigest()
        session_id = str(uuid.uuid4())
        now = datetime.now(UTC)
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT * FROM management_operator_access_requests WHERE request_id = CAST(%s AS uuid) FOR UPDATE",
                (request_id,),
            )
            row = cursor.fetchone()
            if row is None or row["status"] != "approved":
                raise ManagementConflict("operator access request is not ready for activation")
            if (
                row["requester_issuer"] != actor.issuer
                or row["requester_subject"] != actor.subject_id
            ):
                raise ManagementDenied("only the requesting operator can activate this access")
            self._active_enterprise_user(cursor, actor)
            expires_at = now + timedelta(seconds=int(row["requested_duration_seconds"]))
            scope_digest = managed_digest(
                {
                    "request_id": request_id,
                    "tenant_id": row["tenant_id"],
                    "deployment_id": row["deployment_id"],
                    "actions": row["requested_actions"],
                    "resources": row["requested_resources"],
                    "expires_at": expires_at.isoformat(),
                }
            )
            cursor.execute(
                """
                INSERT INTO management_operator_access_sessions
                  (session_id, request_id, tenant_id, deployment_id, operator_issuer,
                   operator_subject, token_digest, scope_digest, expires_at)
                VALUES (CAST(%s AS uuid), CAST(%s AS uuid), %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
                """,
                (
                    session_id,
                    request_id,
                    row["tenant_id"],
                    row["deployment_id"],
                    actor.issuer,
                    actor.subject_id,
                    token_digest,
                    scope_digest,
                    expires_at,
                ),
            )
            session = dict(cursor.fetchone())
            cursor.execute(
                "UPDATE management_operator_access_requests SET status = 'active', updated_at = now() WHERE request_id = CAST(%s AS uuid)",
                (request_id,),
            )
            self._audit(
                cursor,
                tenant_id=row["tenant_id"],
                deployment_id=row["deployment_id"],
                request_id=request_id,
                session_id=session_id,
                actor_kind="operator",
                actor_issuer=actor.issuer,
                actor_subject=actor.subject_id,
                action="operator_access.activate",
                resource=row["deployment_id"],
                outcome="allowed",
                reason_code="short_lived_exact_scope",
            )
            return session, token

    def authorize(
        self,
        session_id: str,
        session_token: str,
        action: str,
        resource: str,
        actor: OperatorIdentity,
        workload_spiffe_id: str | None = None,
    ) -> dict[str, Any]:
        supplied_digest = hashlib.sha256(session_token.encode()).hexdigest()
        now = datetime.now(UTC)
        with self._transaction() as cursor:
            cursor.execute(
                """
                SELECT s.*, r.requested_actions, r.requested_resources, r.status AS request_status,
                       r.access_kind
                  FROM management_operator_access_sessions s
                  JOIN management_operator_access_requests r ON r.request_id = s.request_id
                 WHERE s.session_id = CAST(%s AS uuid) FOR UPDATE OF s, r
                """,
                (session_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise ManagementDenied("operator access session is unavailable")
            allowed = True
            reason = "exact_scope_active"
            if workload_spiffe_id is not None:
                cursor.execute(
                    """
                    SELECT 1 FROM management_support_gateway_bindings
                     WHERE tenant_id = %s AND deployment_id = %s
                       AND gateway_spiffe_id = %s AND status = 'active'
                     LIMIT 1
                    """,
                    (row["tenant_id"], row["deployment_id"], workload_spiffe_id),
                )
                if cursor.fetchone() is None:
                    allowed, reason = False, "support_gateway_mismatch"
            if allowed and (
                row["operator_issuer"] != actor.issuer
                or row["operator_subject"] != actor.subject_id
            ):
                allowed, reason = False, "operator_identity_mismatch"
            elif allowed and not hmac.compare_digest(row["token_digest"], supplied_digest):
                allowed, reason = False, "session_secret_invalid"
            elif allowed and (row["status"] != "active" or row["request_status"] != "active"):
                allowed, reason = False, "session_revoked"
            elif allowed and row["expires_at"] <= now:
                allowed, reason = False, "session_expired"
                cursor.execute(
                    "UPDATE management_operator_access_sessions SET status = 'expired' WHERE session_id = CAST(%s AS uuid)",
                    (session_id,),
                )
                cursor.execute(
                    "UPDATE management_operator_access_requests SET status = 'expired', updated_at = now() WHERE request_id = %s",
                    (row["request_id"],),
                )
            elif allowed and (
                action not in row["requested_actions"] or resource not in row["requested_resources"]
            ):
                allowed, reason = False, "outside_approved_scope"
            elif allowed:
                try:
                    self._active_enterprise_user(cursor, actor)
                except ManagementDenied:
                    allowed, reason = False, "enterprise_identity_revoked"
            self._audit(
                cursor,
                tenant_id=row["tenant_id"],
                deployment_id=row["deployment_id"],
                request_id=str(row["request_id"]),
                session_id=session_id,
                actor_kind="operator",
                actor_issuer=actor.issuer,
                actor_subject=actor.subject_id,
                action=action,
                resource=resource,
                outcome="allowed" if allowed else "denied",
                reason_code=reason,
            )
            return {
                "allowed": allowed,
                "reason_code": reason,
                "tenant_id": row["tenant_id"],
                "deployment_id": row["deployment_id"],
                "action": action,
                "resource": resource,
                "session_id": row["session_id"],
                "expires_at": row["expires_at"],
            }

    def revoke_by_customer(
        self, request_id: str, tenant_id: str, actor: CustomerIdentity
    ) -> dict[str, Any]:
        with self._transaction() as cursor:
            self._customer_approver(cursor, actor, tenant_id)
            return self._revoke(
                cursor, request_id, tenant_id, "customer", actor.issuer, actor.subject_id
            )

    def revoke_by_operator(self, request_id: str, actor: OperatorIdentity) -> dict[str, Any]:
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT tenant_id FROM management_operator_access_requests WHERE request_id = CAST(%s AS uuid)",
                (request_id,),
            )
            held = cursor.fetchone()
            if held is None:
                raise ManagementDenied("operator access request is unavailable")
            self._operator_role(
                cursor,
                actor,
                held["tenant_id"],
                ("support_approver", "break_glass_approver", "platform_admin"),
            )
            return self._revoke(
                cursor, request_id, held["tenant_id"], "operator", actor.issuer, actor.subject_id
            )

    def _revoke(
        self, cursor, request_id: str, tenant_id: str, actor_kind: str, issuer: str, subject: str
    ) -> dict[str, Any]:
        cursor.execute(
            """
            UPDATE management_operator_access_requests
               SET status = 'revoked', revoked_at = now(), revoked_by_kind = %s, updated_at = now()
             WHERE request_id = CAST(%s AS uuid) AND tenant_id = %s
               AND status NOT IN ('revoked', 'expired', 'completed', 'denied')
            RETURNING *
            """,
            (actor_kind, request_id, tenant_id),
        )
        request = cursor.fetchone()
        if request is None:
            raise ManagementConflict("operator access request is already terminal or unavailable")
        cursor.execute(
            """
            UPDATE management_operator_access_sessions
               SET status = 'revoked', revoked_at = now(), revocation_epoch = revocation_epoch + 1
             WHERE request_id = CAST(%s AS uuid) AND status = 'active'
            RETURNING session_id
            """,
            (request_id,),
        )
        session = cursor.fetchone()
        self._audit(
            cursor,
            tenant_id=tenant_id,
            deployment_id=request["deployment_id"],
            request_id=request_id,
            session_id=str(session["session_id"]) if session else None,
            actor_kind=actor_kind,
            actor_issuer=issuer,
            actor_subject=subject,
            action="operator_access.revoke",
            resource=request["deployment_id"],
            outcome="allowed",
            reason_code="explicit_revocation",
        )
        return dict(request)

    def list_customer_audit(
        self, tenant_id: str, actor: CustomerIdentity, limit: int = 200
    ) -> list[dict[str, Any]]:
        with self._transaction() as cursor:
            self._customer_approver(cursor, actor, tenant_id)
            cursor.execute(
                """
                SELECT event_id, tenant_id, deployment_id, request_id, session_id,
                       actor_kind, actor_issuer, actor_subject, action, resource_ref,
                       outcome, reason_code, occurred_at, previous_event_hash, event_hash
                  FROM management_operator_access_audit
                 WHERE tenant_id = %s ORDER BY audit_id DESC LIMIT %s
                """,
                (tenant_id, min(max(limit, 1), 500)),
            )
            return [dict(row) for row in cursor.fetchall()]
