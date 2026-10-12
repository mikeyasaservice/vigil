"""Tenant-local connector for the managed triage read profile.

This process deliberately contains no backend tool registry. Its database role
can read only the reviewed finding, case-record and episodic-memory tables.
"""
from __future__ import annotations

import hmac
import json
import os
from typing import Any, Optional

import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field


class ConnectorInvokeRequest(BaseModel):
    tool: str = Field(min_length=1)
    args: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    binding_id: Optional[str] = None
    max_rows: int = Field(gt=0)
    timeout_ms: int = Field(gt=0)


app = FastAPI(title="Vigil managed connector", version="1")


def _verified_gateway(request: Request, spiffe_id: Optional[str], proxy_token: Optional[str]) -> None:
    expected_id = os.getenv("VIGIL_GATEWAY_SPIFFE_ID", "")
    expected_token = os.getenv("VIGIL_IDENTITY_PROXY_TOKEN", "")
    scoped = request.scope.get("vigil.verified_spiffe_id")
    held_id = scoped if isinstance(scoped, str) and scoped else spiffe_id
    if not expected_id or not expected_token:
        raise HTTPException(status_code=503, detail="connector workload policy is unavailable")
    if not held_id or not hmac.compare_digest(held_id, expected_id):
        raise HTTPException(status_code=403, detail="connector caller is not the gateway")
    if scoped is None and (not proxy_token or not hmac.compare_digest(proxy_token, expected_token)):
        raise HTTPException(status_code=401, detail="connector requires verified workload identity")


def _binding(body: ConnectorInvokeRequest) -> None:
    builtins = {value.strip() for value in os.getenv("VIGIL_CONNECTOR_BUILTIN_TOOLS", "").split(",") if value.strip()}
    if body.tool in builtins:
        if body.binding_id is not None:
            raise HTTPException(status_code=403, detail="builtin call cannot select an integration")
        return
    try:
        binding = json.loads(os.getenv("VIGIL_CONNECTOR_BINDINGS", "{}"))[body.binding_id or ""]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=403, detail="connector binding is not configured") from exc
    if binding.get("tenant_id") != body.tenant_id or binding.get("tool_name") != body.tool:
        raise HTTPException(status_code=403, detail="connector binding does not own this call")


def _connection():
    return psycopg2.connect(
        host=os.environ["POSTGRES_HOST"], port=int(os.getenv("POSTGRES_PORT", "5432")),
        dbname=os.environ["POSTGRES_DB"], user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"], connect_timeout=5,
    )


def _read(body: ConnectorInvokeRequest) -> list[dict[str, Any]]:
    if body.tool == "recall_entity":
        # The authenticated execution, rather than the worker's arguments, owns
        # the audit attribution.  The connector still uses the shared recall
        # implementation so caps, ordering and the read-log contract cannot
        # drift between standalone and managed execution.
        from core.memory.recall import recall_entity

        args = {
            "entity_keys": body.args.get("entity_keys"),
            "entity_key": body.args.get("entity_key"),
            "as_of": body.args.get("as_of"),
            "caller_kind": "execution",
            "caller_id": body.execution_id,
        }
        return [recall_entity(args)]

    with _connection() as connection, connection.cursor(cursor_factory=RealDictCursor) as cursor:
        cursor.execute("SET TRANSACTION READ ONLY")
        cursor.execute("SET LOCAL statement_timeout = %s", (body.timeout_ms,))
        if body.tool == "get_finding":
            finding_id = str(body.args.get("finding_id") or "")
            if not finding_id:
                raise ValueError("finding_id is required")
            cursor.execute(
                """SELECT to_jsonb(f) || jsonb_build_object(
                       'mitre_predictions', COALESCE((SELECT jsonb_object_agg(m.technique_id, m.confidence)
                         FROM finding_mitre_predictions m WHERE m.finding_id = f.finding_id), '{}'::jsonb)) AS value
                   FROM findings f WHERE f.finding_id = %s LIMIT 1""",
                (finding_id,),
            )
            row = cursor.fetchone()
            return [] if row is None else [dict(row["value"])]
        if body.tool == "case_records":
            case_id = str(body.args.get("case_id") or "")
            if not case_id:
                raise ValueError("case_id is required")
            cursor.execute("SELECT to_jsonb(t) AS value FROM case_tasks t WHERE case_id = %s ORDER BY created_at LIMIT %s", (case_id, body.max_rows))
            tasks = [dict(row["value"]) for row in cursor.fetchall()]
            cursor.execute("SELECT to_jsonb(e) AS value FROM case_escalations e WHERE case_id = %s ORDER BY created_at LIMIT %s", (case_id, body.max_rows))
            escalations = [dict(row["value"]) for row in cursor.fetchall()]
            return [{"tasks": tasks, "escalations": escalations}]
    raise ValueError("tool is not implemented by this connector")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/invoke")
def invoke(body: ConnectorInvokeRequest, request: Request,
           x_vigil_verified_spiffe_id: Optional[str] = Header(default=None),
           x_vigil_identity_proxy_token: Optional[str] = Header(default=None)) -> dict[str, Any]:
    _verified_gateway(request, x_vigil_verified_spiffe_id, x_vigil_identity_proxy_token)
    _binding(body)
    try:
        rows = _read(body)
    except (KeyError, TypeError, ValueError):
        return {"ok": False, "failure": {"kind": "invalid_args", "detail": "connector arguments were rejected"}}
    except Exception:
        return {"ok": False, "failure": {"kind": "backend_error", "detail": "connector execution failed"}}
    held = rows[: body.max_rows]
    return {"ok": True, "rows": held, "rowCount": len(held), "capped": len(rows) > body.max_rows, "sourceSystem": "vigil"}
