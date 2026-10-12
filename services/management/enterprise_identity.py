from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import uuid
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote, urlencode
from xml.sax.saxutils import escape

import jwt
import psycopg2
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from lxml import etree
from psycopg2.extras import Json, RealDictCursor
from services.management.contracts import IdentityProviderRequest
from services.management.store import (
    ManagementConflict,
    ManagementDenied,
    ManagementUnavailable,
)
from signxml import DigestAlgorithm, SignatureConfiguration, SignatureMethod, XMLVerifier

SAML_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"


@dataclass(frozen=True)
class FederatedPrincipal:
    issuer: str
    subject_id: str
    token_id: str
    provider_id: str
    session_id: str
    assurance: tuple[str, ...]


class EnterpriseIdentityStore:
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
            raise ManagementConflict(
                "enterprise identity state conflicts with durable policy"
            ) from exc
        except psycopg2.Error as exc:
            raise ManagementUnavailable("enterprise identity transaction failed") from exc
        finally:
            connection.close()

    @staticmethod
    def _platform_admin(cursor, issuer: str, subject_id: str) -> None:
        cursor.execute(
            """
            SELECT 1 FROM management_operator_scopes
             WHERE issuer = %s AND subject_id = %s AND tenant_id IS NULL
               AND role = 'platform_admin' AND status = 'active' LIMIT 1
            """,
            (issuer, subject_id),
        )
        if cursor.fetchone() is None:
            raise ManagementDenied("platform administrator scope is required")

    def configure_provider(self, request: IdentityProviderRequest, actor) -> dict[str, Any]:
        if not request.required_acr and not request.required_amr:
            raise ManagementDenied("enterprise identity providers require an MFA assurance policy")
        if request.protocol == "oidc":
            keys = (request.oidc_jwks or {}).get("keys", [])
            if (
                not keys
                or any(key.get("d") for key in keys)
                or any(not key.get("kid") for key in keys)
            ):
                raise ManagementDenied("OIDC JWKS must contain identified public keys only")
        else:
            try:
                x509.load_pem_x509_certificate(request.saml_signing_certificate.encode())
            except (AttributeError, ValueError) as exc:
                raise ManagementDenied("SAML signing certificate is invalid") from exc
        with self._transaction() as cursor:
            self._platform_admin(cursor, actor.issuer, actor.subject_id)
            cursor.execute(
                """
                INSERT INTO management_identity_providers
                  (provider_id, protocol, issuer, audience, oidc_jwks, oidc_algorithms,
                   required_acr, required_amr, saml_sso_url, saml_entity_id,
                   saml_acs_url, saml_signing_certificate, max_session_seconds)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (provider_id) DO UPDATE SET
                  issuer = EXCLUDED.issuer, audience = EXCLUDED.audience,
                  oidc_jwks = EXCLUDED.oidc_jwks, oidc_algorithms = EXCLUDED.oidc_algorithms,
                  required_acr = EXCLUDED.required_acr, required_amr = EXCLUDED.required_amr,
                  saml_sso_url = EXCLUDED.saml_sso_url,
                  saml_entity_id = EXCLUDED.saml_entity_id,
                  saml_acs_url = EXCLUDED.saml_acs_url,
                  saml_signing_certificate = EXCLUDED.saml_signing_certificate,
                  max_session_seconds = EXCLUDED.max_session_seconds,
                  status = 'active', updated_at = now()
                WHERE management_identity_providers.protocol = EXCLUDED.protocol
                RETURNING provider_id, protocol, issuer, audience, oidc_algorithms,
                          required_acr, required_amr, saml_sso_url, saml_entity_id,
                          saml_acs_url, max_session_seconds, status, created_at, updated_at
                """,
                (
                    request.provider_id,
                    request.protocol,
                    request.issuer,
                    request.audience,
                    Json(request.oidc_jwks) if request.oidc_jwks is not None else None,
                    request.oidc_algorithms,
                    request.required_acr,
                    request.required_amr,
                    request.saml_sso_url,
                    request.saml_entity_id,
                    request.saml_acs_url,
                    request.saml_signing_certificate,
                    request.max_session_seconds,
                ),
            )
            row = cursor.fetchone()
            if row is None:
                raise ManagementConflict("identity provider protocol cannot be changed in place")
            return dict(row)

    def issue_scim_token(
        self, provider_id: str, expires_at: datetime, actor
    ) -> tuple[dict[str, Any], str]:
        now = datetime.now(UTC)
        expiry = expires_at.astimezone(UTC)
        if expiry <= now or expiry > now + timedelta(days=90):
            raise ManagementDenied("SCIM token must expire within 90 days")
        token = secrets.token_urlsafe(48)
        digest = hashlib.sha256(token.encode()).hexdigest()
        token_id = str(uuid.uuid4())
        with self._transaction() as cursor:
            self._platform_admin(cursor, actor.issuer, actor.subject_id)
            cursor.execute(
                """
                INSERT INTO management_scim_tokens
                  (token_id, provider_id, token_digest, expires_at, created_by_issuer, created_by_subject)
                SELECT CAST(%s AS uuid), provider_id, %s, %s, %s, %s
                  FROM management_identity_providers
                 WHERE provider_id = %s AND status = 'active'
                RETURNING token_id, provider_id, expires_at, status, created_at
                """,
                (token_id, digest, expiry, actor.issuer, actor.subject_id, provider_id),
            )
            row = cursor.fetchone()
            if row is None:
                raise ManagementDenied("identity provider is unavailable")
            return dict(row), token

    def scim_provider(self, authorization: str | None) -> str:
        if not authorization or not authorization.startswith("Bearer "):
            raise ManagementDenied("SCIM bearer token is required")
        token = authorization.removeprefix("Bearer ").strip()
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self._transaction() as cursor:
            cursor.execute(
                """
                SELECT t.provider_id, t.token_digest
                  FROM management_scim_tokens t
                  JOIN management_identity_providers p ON p.provider_id = t.provider_id
                 WHERE t.token_digest = %s AND t.status = 'active' AND t.expires_at > now()
                   AND p.status = 'active'
                """,
                (digest,),
            )
            row = cursor.fetchone()
            if row is None or not hmac.compare_digest(row["token_digest"], digest):
                raise ManagementDenied("SCIM bearer token is invalid")
            return str(row["provider_id"])

    def upsert_scim_user(
        self, provider_id: str, document: dict[str, Any], external_id: str | None = None
    ) -> dict[str, Any]:
        user_name = str(document.get("userName", "")).strip()
        target_id = external_id or str(document.get("externalId", "")).strip()
        if not user_name or not target_id:
            raise ManagementDenied("SCIM userName and immutable externalId are required")
        active = bool(document.get("active", True))
        display_name = (
            str(document.get("displayName") or document.get("name", {}).get("formatted") or "")[
                :512
            ]
            or None
        )
        with self._transaction() as cursor:
            cursor.execute(
                """
                INSERT INTO management_enterprise_users
                  (provider_id, external_id, user_name, display_name, active)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (provider_id, external_id) DO UPDATE SET
                  user_name = EXCLUDED.user_name, display_name = EXCLUDED.display_name,
                  active = EXCLUDED.active, scim_version = gen_random_uuid(),
                  last_synced_at = now(), updated_at = now()
                RETURNING *
                """,
                (provider_id, target_id, user_name, display_name, active),
            )
            row = dict(cursor.fetchone())
            if not active:
                self._deprovision(cursor, provider_id, target_id)
            return self._scim_user(row)

    def get_scim_user(self, provider_id: str, external_id: str) -> dict[str, Any] | None:
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT * FROM management_enterprise_users WHERE provider_id = %s AND external_id = %s",
                (provider_id, external_id),
            )
            row = cursor.fetchone()
            return self._scim_user(dict(row)) if row else None

    def list_scim_users(self, provider_id: str, filter_value: str | None) -> list[dict[str, Any]]:
        with self._transaction() as cursor:
            if filter_value:
                prefix = 'userName eq "'
                if not filter_value.startswith(prefix) or not filter_value.endswith('"'):
                    raise ManagementDenied("only exact userName SCIM filters are supported")
                user_name = filter_value[len(prefix) : -1]
                cursor.execute(
                    "SELECT * FROM management_enterprise_users WHERE provider_id = %s AND user_name = %s ORDER BY user_name",
                    (provider_id, user_name),
                )
            else:
                cursor.execute(
                    "SELECT * FROM management_enterprise_users WHERE provider_id = %s ORDER BY user_name LIMIT 1000",
                    (provider_id,),
                )
            return [self._scim_user(dict(row)) for row in cursor.fetchall()]

    def deactivate_scim_user(self, provider_id: str, external_id: str) -> None:
        with self._transaction() as cursor:
            cursor.execute(
                """
                UPDATE management_enterprise_users
                   SET active = false, scim_version = gen_random_uuid(),
                       last_synced_at = now(), updated_at = now()
                 WHERE provider_id = %s AND external_id = %s AND active
                RETURNING external_id
                """,
                (provider_id, external_id),
            )
            if cursor.fetchone() is None:
                raise ManagementDenied("SCIM user is unavailable")
            self._deprovision(cursor, provider_id, external_id)

    def upsert_scim_group(
        self, provider_id: str, document: dict[str, Any], external_id: str | None = None
    ) -> dict[str, Any]:
        target_id = external_id or str(document.get("externalId", "")).strip()
        display_name = str(document.get("displayName", "")).strip()
        members = sorted(
            {str(member.get("value", "")).strip() for member in document.get("members", [])}
        )
        if not target_id or not display_name or any(not member for member in members):
            raise ManagementDenied(
                "SCIM group externalId, displayName, and member values are required"
            )
        with self._transaction() as cursor:
            if members:
                cursor.execute(
                    "SELECT external_id FROM management_enterprise_users WHERE provider_id = %s AND external_id = ANY(%s)",
                    (provider_id, members),
                )
                if {str(row["external_id"]) for row in cursor.fetchall()} != set(members):
                    raise ManagementDenied("SCIM group contains an unknown enterprise user")
            cursor.execute(
                """
                INSERT INTO management_enterprise_groups (provider_id, external_id, display_name)
                VALUES (%s, %s, %s)
                ON CONFLICT (provider_id, external_id) DO UPDATE SET
                  display_name = EXCLUDED.display_name, scim_version = gen_random_uuid(), updated_at = now()
                RETURNING *
                """,
                (provider_id, target_id, display_name),
            )
            row = dict(cursor.fetchone())
            cursor.execute(
                "DELETE FROM management_enterprise_group_members WHERE provider_id = %s AND group_external_id = %s",
                (provider_id, target_id),
            )
            for member in members:
                cursor.execute(
                    "INSERT INTO management_enterprise_group_members (provider_id, group_external_id, user_external_id) VALUES (%s, %s, %s)",
                    (provider_id, target_id, member),
                )
            return self._scim_group(row, members)

    def get_scim_group(self, provider_id: str, external_id: str) -> dict[str, Any] | None:
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT * FROM management_enterprise_groups WHERE provider_id = %s AND external_id = %s",
                (provider_id, external_id),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            cursor.execute(
                "SELECT user_external_id FROM management_enterprise_group_members WHERE provider_id = %s AND group_external_id = %s ORDER BY user_external_id",
                (provider_id, external_id),
            )
            return self._scim_group(
                dict(row), [str(item["user_external_id"]) for item in cursor.fetchall()]
            )

    @staticmethod
    def _scim_group(row: dict[str, Any], members: list[str]) -> dict[str, Any]:
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": row["external_id"],
            "externalId": row["external_id"],
            "displayName": row["display_name"],
            "members": [{"value": member} for member in members],
            "meta": {
                "resourceType": "Group",
                "version": f'W/"{row["scim_version"]}"',
                "created": row["created_at"].isoformat(),
                "lastModified": row["updated_at"].isoformat(),
            },
        }

    @staticmethod
    def _scim_user(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": row["external_id"],
            "externalId": row["external_id"],
            "userName": row["user_name"],
            "displayName": row["display_name"],
            "active": row["active"],
            "meta": {
                "resourceType": "User",
                "version": f'W/"{row["scim_version"]}"',
                "created": row["created_at"].isoformat(),
                "lastModified": row["updated_at"].isoformat(),
            },
        }

    @staticmethod
    def _deprovision(cursor, provider_id: str, subject_id: str) -> None:
        cursor.execute(
            """
            UPDATE management_operator_scopes SET status = 'revoked', membership_version = membership_version + 1
             WHERE subject_id = %s AND status = 'active'
               AND issuer = (SELECT issuer FROM management_identity_providers WHERE provider_id = %s);
            UPDATE management_operator_access_requests
               SET status = 'revoked', revoked_at = now(), revoked_by_kind = 'scim', updated_at = now()
             WHERE requester_subject = %s
               AND requester_issuer = (SELECT issuer FROM management_identity_providers WHERE provider_id = %s)
               AND status IN ('pending_customer', 'pending_provider', 'approved', 'active');
            UPDATE management_operator_access_sessions s
               SET status = 'revoked', revoked_at = now(), revocation_epoch = revocation_epoch + 1
              FROM management_operator_access_requests r
             WHERE s.request_id = r.request_id AND r.requester_subject = %s
               AND r.requester_issuer = (SELECT issuer FROM management_identity_providers WHERE provider_id = %s)
               AND s.status = 'active'
            """,
            (subject_id, provider_id, subject_id, provider_id, subject_id, provider_id),
        )

    def authenticate(self, token: str) -> FederatedPrincipal:
        try:
            unverified = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
            issuer = str(unverified.get("iss", ""))
        except jwt.PyJWTError as exc:
            raise ManagementDenied("federated bearer token is malformed") from exc
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT * FROM management_identity_providers WHERE issuer = %s AND protocol = 'oidc' AND status = 'active'",
                (issuer,),
            )
            provider = cursor.fetchone()
        if provider is not None:
            payload = self._verify_oidc(token, dict(provider))
            provider_id = provider["provider_id"]
        else:
            payload = self._verify_saml_session(token)
            provider_id = str(payload.get("idp", ""))
            with self._transaction() as cursor:
                cursor.execute(
                    "SELECT issuer FROM management_identity_providers WHERE provider_id = %s AND protocol = 'saml' AND status = 'active'",
                    (provider_id,),
                )
                provider = cursor.fetchone()
            if provider is None:
                raise ManagementDenied("SAML identity provider is inactive")
            issuer = str(provider["issuer"])
        subject = str(payload.get("sub", ""))
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT active FROM management_enterprise_users WHERE provider_id = %s AND external_id = %s",
                (provider_id, subject),
            )
            user = cursor.fetchone()
        if user is None or not user["active"]:
            raise ManagementDenied("enterprise user is not active")
        assurance_values = [str(value) for value in payload.get("amr", [])]
        if payload.get("acr"):
            assurance_values.append("acr:" + str(payload["acr"]))
        assurance = tuple(assurance_values)
        return FederatedPrincipal(
            issuer=issuer,
            subject_id=subject,
            token_id=str(payload["jti"]),
            provider_id=str(provider_id),
            session_id=str(payload.get("sid", payload["jti"])),
            assurance=assurance,
        )

    @staticmethod
    def _verify_oidc(token: str, provider: dict[str, Any]) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            algorithm = header.get("alg")
            if not kid or algorithm not in provider["oidc_algorithms"]:
                raise ManagementDenied("OIDC token algorithm or key identifier is not allowed")
            jwks = provider["oidc_jwks"]
            matching = [
                key for key in jwks.get("keys", []) if key.get("kid") == kid and not key.get("d")
            ]
            if len(matching) != 1:
                raise ManagementDenied("OIDC signing key is unavailable or ambiguous")
            signing_key = jwt.PyJWK.from_dict(matching[0], algorithm=algorithm).key
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=[algorithm],
                issuer=provider["issuer"],
                audience=provider["audience"],
                options={"require": ["sub", "iss", "aud", "exp", "iat", "jti", "sid"]},
            )
        except jwt.PyJWTError as exc:
            raise ManagementDenied("OIDC bearer token is invalid") from exc
        EnterpriseIdentityStore._validate_lifetime(payload, int(provider["max_session_seconds"]))
        acr = str(payload.get("acr", ""))
        amr = {str(value) for value in payload.get("amr", [])}
        if provider["required_acr"] and acr not in provider["required_acr"]:
            raise ManagementDenied("OIDC authentication context is insufficient")
        if not set(provider["required_amr"]).issubset(amr):
            raise ManagementDenied("OIDC authentication methods are insufficient")
        return payload

    @staticmethod
    def _validate_lifetime(payload: dict[str, Any], maximum_seconds: int) -> None:
        now = datetime.now(UTC)
        issued = datetime.fromtimestamp(int(payload["iat"]), UTC)
        expires = datetime.fromtimestamp(int(payload["exp"]), UTC)
        if (
            issued > now + timedelta(seconds=30)
            or expires <= now
            or expires - issued > timedelta(seconds=maximum_seconds)
        ):
            raise ManagementDenied("federated token lifetime is invalid")

    @staticmethod
    def _verify_saml_session(token: str) -> dict[str, Any]:
        issuer = os.getenv("AUTOBOT_FEDERATED_SESSION_ISSUER", "")
        audience = os.getenv("AUTOBOT_FEDERATED_SESSION_AUDIENCE", "")
        public_key = os.getenv("AUTOBOT_FEDERATED_SESSION_PUBLIC_KEY", "")
        if not issuer or not audience or not public_key:
            raise ManagementUnavailable("SAML session trust is unavailable")
        try:
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["EdDSA"],
                issuer=issuer,
                audience=audience,
                options={"require": ["sub", "iss", "aud", "exp", "iat", "jti", "sid", "idp"]},
            )
        except jwt.PyJWTError as exc:
            raise ManagementDenied("SAML session token is invalid") from exc
        EnterpriseIdentityStore._validate_lifetime(payload, 600)
        return payload

    def begin_saml_login(self, provider_id: str) -> dict[str, Any]:
        request_id = "_" + uuid.uuid4().hex
        relay_state = secrets.token_urlsafe(32)
        relay_digest = hashlib.sha256(relay_state.encode()).hexdigest()
        now = datetime.now(UTC)
        expiry = now + timedelta(minutes=5)
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT * FROM management_identity_providers WHERE provider_id = %s AND protocol = 'saml' AND status = 'active'",
                (provider_id,),
            )
            provider = cursor.fetchone()
            if provider is None:
                raise ManagementDenied("SAML identity provider is unavailable")
            cursor.execute(
                "INSERT INTO management_saml_auth_requests (request_id, provider_id, relay_state_digest, expires_at) VALUES (%s, %s, %s, %s)",
                (request_id, provider_id, relay_digest, expiry),
            )
        issue_instant = now.isoformat(timespec="seconds").replace("+00:00", "Z")
        xml = (
            f'<samlp:AuthnRequest xmlns:samlp="{SAML_PROTOCOL}" xmlns:saml="{SAML_ASSERTION}" '
            f'ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}" '
            f'Destination="{escape(provider["saml_sso_url"])}" '
            f'AssertionConsumerServiceURL="{escape(provider["saml_acs_url"])}">'
            f"<saml:Issuer>{escape(provider['audience'])}</saml:Issuer>"
            f'<samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"/>'
            f"</samlp:AuthnRequest>"
        ).encode()
        compressed = zlib.compress(xml)[2:-4]
        encoded = base64.b64encode(compressed).decode()
        return {
            "provider_id": provider_id,
            "request_id": request_id,
            "relay_state": relay_state,
            "sso_url": provider["saml_sso_url"],
            "saml_request": encoded,
            "expires_at": expiry,
            "redirect_url": provider["saml_sso_url"]
            + "?"
            + urlencode({"SAMLRequest": encoded, "RelayState": relay_state}, quote_via=quote),
        }

    def consume_saml_assertion(
        self, provider_id: str, saml_response: str, relay_state: str
    ) -> tuple[str, datetime]:
        relay_digest = hashlib.sha256(relay_state.encode()).hexdigest()
        try:
            xml_bytes = base64.b64decode(saml_response, validate=True)
        except ValueError as exc:
            raise ManagementDenied("SAML response encoding is invalid") from exc
        parser = etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            load_dtd=False,
            huge_tree=False,
            remove_comments=True,
        )
        try:
            root = etree.fromstring(xml_bytes, parser=parser)
        except etree.XMLSyntaxError as exc:
            raise ManagementDenied("SAML response XML is invalid") from exc
        if (
            root.tag != f"{{{SAML_PROTOCOL}}}Response"
            or len(root.findall(f"{{{SAML_ASSERTION}}}Assertion")) != 1
        ):
            raise ManagementDenied("SAML response shape is invalid")
        with self._transaction() as cursor:
            cursor.execute(
                "SELECT * FROM management_identity_providers WHERE provider_id = %s AND protocol = 'saml' AND status = 'active'",
                (provider_id,),
            )
            provider = cursor.fetchone()
            cursor.execute(
                "SELECT * FROM management_saml_auth_requests WHERE provider_id = %s AND relay_state_digest = %s FOR UPDATE",
                (provider_id, relay_digest),
            )
            auth_request = cursor.fetchone()
            if (
                provider is None
                or auth_request is None
                or auth_request["consumed_at"] is not None
                or auth_request["expires_at"] <= datetime.now(UTC)
            ):
                raise ManagementDenied("SAML login request is invalid or expired")
            if (
                root.get("InResponseTo") != auth_request["request_id"]
                or root.get("Destination") != provider["saml_acs_url"]
            ):
                raise ManagementDenied("SAML response target does not match the login request")
            try:
                verified = XMLVerifier().verify(
                    root,
                    x509_cert=provider["saml_signing_certificate"],
                    expect_config=SignatureConfiguration(
                        require_x509=True,
                        location=f"./{{{SAML_ASSERTION}}}Assertion/",
                        expect_references=1,
                        signature_methods=frozenset(
                            {SignatureMethod.RSA_SHA256, SignatureMethod.ECDSA_SHA256}
                        ),
                        digest_algorithms=frozenset({DigestAlgorithm.SHA256}),
                    ),
                )
            except Exception as exc:
                raise ManagementDenied("SAML assertion signature is invalid") from exc
            assertion = verified.signed_xml
            subject, assertion_id, session_id, assertion_expiry, authn_context = (
                self._validate_saml_assertion(assertion, provider, auth_request["request_id"])
            )
            cursor.execute(
                "SELECT active FROM management_enterprise_users WHERE provider_id = %s AND external_id = %s",
                (provider_id, subject),
            )
            user = cursor.fetchone()
            if user is None or not user["active"]:
                raise ManagementDenied("SAML enterprise user is inactive")
            cursor.execute(
                "INSERT INTO management_saml_assertion_replay (provider_id, assertion_id, subject_id, expires_at) VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING RETURNING assertion_id",
                (provider_id, assertion_id, subject, assertion_expiry),
            )
            if cursor.fetchone() is None:
                raise ManagementDenied("SAML assertion was replayed")
            cursor.execute(
                "UPDATE management_saml_auth_requests SET consumed_at = now() WHERE request_id = %s",
                (auth_request["request_id"],),
            )
        expiry = min(
            datetime.now(UTC) + timedelta(seconds=int(provider["max_session_seconds"])),
            assertion_expiry,
        )
        token = self._issue_saml_session(provider_id, subject, session_id, authn_context, expiry)
        return token, expiry

    @staticmethod
    def _validate_saml_assertion(
        assertion, provider, request_id: str
    ) -> tuple[str, str, str, datetime, str]:
        ns = {"saml": SAML_ASSERTION}
        issuer = assertion.findtext("saml:Issuer", namespaces=ns)
        subject = assertion.findtext("saml:Subject/saml:NameID", namespaces=ns)
        conditions = assertion.find("saml:Conditions", namespaces=ns)
        confirmation = assertion.find(
            "saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", namespaces=ns
        )
        authn = assertion.find("saml:AuthnStatement", namespaces=ns)
        authn_context = assertion.findtext(
            "saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef",
            namespaces=ns,
        )
        audiences = assertion.xpath(
            "saml:Conditions/saml:AudienceRestriction/saml:Audience/text()", namespaces=ns
        )
        if not subject or issuer != provider["issuer"] or provider["audience"] not in audiences:
            raise ManagementDenied("SAML assertion issuer, subject, or audience is invalid")
        if conditions is None or confirmation is None or authn is None:
            raise ManagementDenied("SAML assertion conditions are incomplete")
        if (
            confirmation.get("InResponseTo") != request_id
            or confirmation.get("Recipient") != provider["saml_acs_url"]
        ):
            raise ManagementDenied("SAML subject confirmation is not bound to this login")
        now = datetime.now(UTC)
        not_before = _saml_time(conditions.get("NotBefore"))
        expiry = min(
            _saml_time(conditions.get("NotOnOrAfter")), _saml_time(confirmation.get("NotOnOrAfter"))
        )
        if not_before > now + timedelta(seconds=30) or expiry <= now - timedelta(seconds=30):
            raise ManagementDenied("SAML assertion is outside its validity window")
        assertion_id = str(assertion.get("ID", ""))
        session_id = str(authn.get("SessionIndex", ""))
        if not assertion_id or not session_id:
            raise ManagementDenied("SAML assertion identifiers are incomplete")
        if provider["required_acr"] and authn_context not in provider["required_acr"]:
            raise ManagementDenied("SAML authentication context is insufficient")
        if not authn_context:
            raise ManagementDenied("SAML authentication context is missing")
        return subject, assertion_id, session_id, expiry, authn_context

    @staticmethod
    def _issue_saml_session(
        provider_id: str,
        subject: str,
        session_id: str,
        authn_context: str,
        expiry: datetime,
    ) -> str:
        private_key_pem = os.getenv("AUTOBOT_FEDERATED_SESSION_PRIVATE_KEY", "")
        issuer = os.getenv("AUTOBOT_FEDERATED_SESSION_ISSUER", "")
        audience = os.getenv("AUTOBOT_FEDERATED_SESSION_AUDIENCE", "")
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(), password=None
            )
        except (TypeError, ValueError) as exc:
            raise ManagementUnavailable("SAML session signing key is unavailable") from exc
        if not isinstance(private_key, Ed25519PrivateKey) or not issuer or not audience:
            raise ManagementUnavailable("SAML session signing trust is unavailable")
        now = datetime.now(UTC)
        return jwt.encode(
            {
                "iss": issuer,
                "aud": audience,
                "sub": subject,
                "idp": provider_id,
                "iat": int(now.timestamp()),
                "exp": int(expiry.timestamp()),
                "jti": str(uuid.uuid4()),
                "sid": session_id,
                "amr": ["saml"],
                "acr": authn_context,
            },
            private_key,
            algorithm="EdDSA",
        )


def _saml_time(value: str | None) -> datetime:
    if not value:
        raise ManagementDenied("SAML assertion timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ManagementDenied("SAML assertion timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise ManagementDenied("SAML assertion timestamp requires a timezone")
    return parsed.astimezone(UTC)
