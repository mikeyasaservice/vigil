#!/usr/bin/env python3
"""Run deployed A/B managed-runtime qualification against real AWS services.

Credentials and raw evidence stay under the mode-0700 qualification work root.
The committed report receives only sanitized assertions and resource digests.
"""

from __future__ import annotations

import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(os.getenv("VIGIL_AWS_QUALIFICATION_ROOT", "/tmp/vigil-aws-qualification"))
AWS_CONFIG = ROOT / "aws-config"
RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
EVIDENCE = ROOT / "evidence" / RUN_ID
CREDS = ROOT / "qualification-credentials.json"
TENANTS = ("a", "b")


@dataclass(frozen=True)
class Tenant:
    name: str
    tenant_id: str
    deployment_id: str
    port: int

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


TARGETS = {
    name: Tenant(name, f"tenant-qual-{name}", f"deployment-qual-{name}", 16987 if name == "a" else 17987)
    for name in TENANTS
}


def aws_env(name: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        AWS_CONFIG_FILE=str(AWS_CONFIG),
        AWS_PROFILE=f"vigil-tenant-{name}",
        AWS_REGION="us-east-1",
        AWS_DEFAULT_REGION="us-east-1",
        AWS_EC2_METADATA_DISABLED="true",
        KUBECONFIG=str(ROOT / f"tenant-{name}" / "kubeconfig"),
    )
    return env


def kubectl(name: str, *args: str, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["kubectl", *args],
        env=aws_env(name),
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        combined = (result.stdout + "\n" + result.stderr).strip().splitlines()
        detail = " | ".join(combined[-8:]) if combined else "no output"
        raise RuntimeError(f"kubectl tenant {name} failed ({result.returncode}): {detail}")
    return result


def request(base: str, method: str, path: str, body: Any | None = None, token: str | None = None, headers: dict[str, str] | None = None) -> tuple[int, Any]:
    payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    outgoing = {"Accept": "application/json", **(headers or {})}
    if payload is not None:
        outgoing["Content-Type"] = "application/json"
    if token:
        outgoing["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base + path, method=method, data=payload, headers=outgoing)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = {"detail": "non-json error"}
        return exc.code, parsed


def wait_port(port: int) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.25)
    raise RuntimeError(f"port-forward {port} did not become ready")


def start_forwards() -> list[subprocess.Popen[str]]:
    processes: list[subprocess.Popen[str]] = []
    for name, target in TARGETS.items():
        process = subprocess.Popen(
            ["kubectl", "port-forward", "-n", "vigil", "svc/vigil-backend", f"{target.port}:6987"],
            env=aws_env(name),
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        processes.append(process)
        wait_port(target.port)
    return processes


def stop_forwards(processes: list[subprocess.Popen[str]]) -> None:
    for process in processes:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
    for process in processes:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)


def credentials() -> dict[str, dict[str, str]]:
    if CREDS.exists():
        result = json.loads(CREDS.read_text())
        changed = False
        for name in TENANTS:
            if str(result[name]["email"]).endswith(".invalid"):
                result[name]["email"] = f"qual-admin-{name}@example.com"
                changed = True
        if changed:
            CREDS.write_text(json.dumps(result, indent=2) + "\n")
            CREDS.chmod(0o600)
        return result
    result = {
        name: {
            "username": f"qual_admin_{name}",
            "email": f"qual-admin-{name}@example.com",
            "password": "Vg!7_" + secrets.token_urlsafe(30),
        }
        for name in TENANTS
    }
    CREDS.write_text(json.dumps(result, indent=2) + "\n")
    CREDS.chmod(0o600)
    return result


def bootstrap_and_login(target: Tenant, credential: dict[str, str]) -> tuple[str, str]:
    status, state = request(target.base_url, "GET", "/api/auth/bootstrap")
    if status != 200:
        raise RuntimeError(f"tenant {target.name} bootstrap status failed: {status}")
    if state["required"]:
        status, user = request(
            target.base_url,
            "POST",
            "/api/auth/bootstrap",
            {**credential, "full_name": f"Qualification admin {target.name.upper()}"},
        )
        if status != 201:
            raise RuntimeError(f"tenant {target.name} bootstrap failed: {status} {user}")
    status, login = request(
        target.base_url,
        "POST",
        "/api/auth/login",
        {"username_or_email": credential["username"], "password": credential["password"]},
    )
    if status != 200:
        raise RuntimeError(f"tenant {target.name} login failed: {status} {login}")
    return str(login["access_token"]), str(login["user"]["user_id"])


SEED_PROGRAM = r'''
import base64
import hashlib
import json
import os
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from core.agents.managed_execution import Ed25519Signer
from core.agents.managed_store import program_registry_payload
from core.storage.connection import get_db_session, init_database
from services.reasoner.programs.triage_v1 import artifact_digest

tenant = os.environ["QUAL_TENANT"]
deployment = os.environ["QUAL_DEPLOYMENT"]
subject = os.environ["QUAL_SUBJECT"]
issuer = os.environ["VIGIL_AUTH_ISSUER"]
canary = os.environ["QUAL_CANARY"]
incarnation = os.environ["QUAL_INCARNATION"]
private_raw = os.environ["VIGIL_MANAGED_AUTHORITY_PRIVATE_KEY"]
private = Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(private_raw + "=" * (-len(private_raw) % 4)))
public_raw = os.environ["VIGIL_MANAGED_AUTHORITY_PUBLIC_KEY"]
program_digest = artifact_digest()
manifest_path = Path("/app/services/reasoner/programs/triage-v1.manifest.json")
manifest = json.loads(manifest_path.read_text())
model_digest = "sha256:" + hashlib.sha256(json.dumps(manifest["model_configuration"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
dependency_digest = "sha256:" + hashlib.sha256(Path("/app/services/reasoner/requirements.lock").read_bytes()).hexdigest()
row = {
    "tenant_id": tenant,
    "program_id": "triage-dspy-v1",
    "program_digest": program_digest,
    "model_config_digest": model_digest,
    "dependency_digest": dependency_digest,
    "status": "active",
}
signature = Ed25519Signer(private).sign(program_registry_payload(row))
init_database(create_tables=False)
with get_db_session() as session:
    session.execute(text("""
        INSERT INTO managed_deployments
          (deployment_id, tenant_id, incarnation, policy_version, revocation_epoch, authority_public_key, status)
        VALUES (:deployment, :tenant, CAST(:incarnation AS uuid), 'managed-v1', 0, :public_key, 'active')
        ON CONFLICT (deployment_id) DO UPDATE SET
          tenant_id=EXCLUDED.tenant_id, incarnation=EXCLUDED.incarnation,
          policy_version=EXCLUDED.policy_version, authority_public_key=EXCLUDED.authority_public_key,
          status='active'
    """), {"deployment": deployment, "tenant": tenant, "incarnation": incarnation, "public_key": public_raw})
    session.execute(text("""
        INSERT INTO managed_memberships (tenant_id, subject_id, issuer, roles, membership_version, status)
        VALUES (:tenant, :subject, :issuer, CAST(:roles AS jsonb), 1, 'active')
        ON CONFLICT (tenant_id, subject_id, issuer) DO UPDATE SET
          roles=EXCLUDED.roles, membership_version=managed_memberships.membership_version + 1, status='active'
    """), {"tenant": tenant, "subject": subject, "issuer": issuer, "roles": json.dumps(["admin", "approver"])})
    session.execute(text("""
        INSERT INTO managed_program_registry
          (tenant_id, program_id, program_digest, artifact_signature, model_config_digest,
           dependency_digest, status, approved_by, activated_at)
        VALUES (:tenant, 'triage-dspy-v1', :digest, :signature, :model, :dependency,
                'active', :subject, now())
        ON CONFLICT (tenant_id, program_id, program_digest) DO NOTHING
    """), {"tenant": tenant, "digest": program_digest, "signature": signature,
             "model": model_digest, "dependency": dependency_digest, "subject": subject})
    session.execute(text("""
        INSERT INTO findings
          (finding_id, title, description, data_source, external_id, severity, status, entity_context)
        VALUES ('qualification-collision', 'Qualification collision', :canary,
                'qualification', :external_id, 'high', 'new', CAST(:context AS jsonb))
        ON CONFLICT (finding_id) DO UPDATE SET description=EXCLUDED.description,
          entity_context=EXCLUDED.entity_context, updated_at=now()
    """), {"canary": canary, "external_id": "collision-" + tenant,
             "context": json.dumps({"tenant_canary": canary})})
    session.commit()
print(json.dumps({"program_digest": program_digest, "seeded": True}))
'''


def seed(target: Tenant, subject: str) -> dict[str, Any]:
    incarnation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" if target.name == "a" else "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    canary = f"VIGIL-QUAL-{target.name.upper()}-ONLY-CANARY"
    result = kubectl(
        target.name,
        "exec", "-i", "-n", "vigil", "deploy/vigil-backend", "-c", "backend", "--",
        "env", f"QUAL_TENANT={target.tenant_id}", f"QUAL_DEPLOYMENT={target.deployment_id}",
        f"QUAL_SUBJECT={subject}", f"QUAL_CANARY={canary}", f"QUAL_INCARNATION={incarnation}",
        "python", "-",
        input_text=SEED_PROGRAM,
    )
    return json.loads(result.stdout.strip().splitlines()[-1])


def wait_run(target: Tenant, token: str, run_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 180
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        status, last = request(target.base_url, "GET", f"/api/v2/agent-runs/{run_id}", token=token)
        if status != 200:
            raise RuntimeError(f"run lookup failed for tenant {target.name}: {status} {last}")
        if last["status"] in {"succeeded", "failed", "cancelled"}:
            return last
        time.sleep(2)
    raise RuntimeError(f"tenant {target.name} run did not finish: {last}")


def worker_database_boundary(name: str) -> dict[str, Any]:
    script = r'''
import pg from "pg";
const c = new pg.Client({host:process.env.POSTGRES_HOST, port:Number(process.env.POSTGRES_PORT), database:process.env.POSTGRES_DB, user:process.env.POSTGRES_USER, password:process.env.POSTGRES_PASSWORD, ssl:{rejectUnauthorized:true}});
await c.connect();
const who = await c.query("select current_user");
const initialPath = await c.query("show search_path");
const good = await c.query("select count(*)::int as n from agent_run_leases");
let protectedDenied=false, domainDenied=false, joinDenied=false, roleDenied=false,
  ddlDenied=false, truncateDenied=false, functionDenied=false, tempDenied=false,
  searchPathDenied=false, recoveredAfterError=false;
try { await c.query("select count(*) from managed_memberships"); } catch(e) { protectedDenied=e.code === "42501"; }
try { await c.query("select count(*) from cases"); } catch(e) { domainDenied=e.code === "42501"; }
try { await c.query("select count(*) from cases c join case_evidence e using (case_id)"); } catch(e) { joinDenied=e.code === "42501"; }
try { await c.query("set role vigil_app"); } catch(e) { roleDenied=e.code === "42501"; }
try { await c.query("create table qualification_forbidden(id int)"); } catch(e) { ddlDenied=e.code === "42501"; }
try { await c.query("create temp table qualification_temp_forbidden(id int)"); } catch(e) { tempDenied=e.code === "42501"; }
try { await c.query("truncate agent_run_leases"); } catch(e) { truncateDenied=e.code === "42501"; }
try { await c.query("create function public.qualification_forbidden() returns int language sql as 'select 1'"); } catch(e) { functionDenied=e.code === "42501"; }
await c.query("set search_path to public, pg_catalog");
try { await c.query("select count(*) from managed_memberships"); } catch(e) { searchPathDenied=e.code === "42501"; }
await c.query("begin");
try { await c.query("select count(*) from managed_memberships"); } catch {}
await c.query("rollback");
recoveredAfterError=(await c.query("select count(*)::int as n from agent_run_leases")).rows[0].n >= 0;
await c.end();
console.log(JSON.stringify({db_user:who.rows[0].current_user,
  initial_search_path:initialPath.rows[0].search_path,ledger_control:good.rows[0].n,
  protected_table_denied:protectedDenied,domain_table_denied:domainDenied,
  join_denied:joinDenied,set_role_denied:roleDenied,ddl_denied:ddlDenied,
  temp_denied:tempDenied,truncate_denied:truncateDenied,
  function_denied:functionDenied,search_path_bypass_denied:searchPathDenied,
  recovered_after_failed_transaction:recoveredAfterError}));
if (!(protectedDenied && domainDenied && joinDenied && roleDenied && ddlDenied &&
      tempDenied && truncateDenied && functionDenied && searchPathDenied &&
      recoveredAfterError)) process.exit(9);
'''
    result = kubectl(name, "exec", "-n", "vigil", "deploy/vigil-agent-worker", "-c", "agent-worker", "--", "node", "--input-type=module", "-e", script)
    return json.loads(result.stdout.strip().splitlines()[-1])


def main() -> int:
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    EVIDENCE.mkdir(parents=True, mode=0o700)
    creds = credentials()
    forwards = start_forwards()
    report: dict[str, Any] = {"run_id": RUN_ID, "started_at": datetime.now(timezone.utc).isoformat(), "tenants": {}, "assertions": {}}
    try:
        tokens: dict[str, str] = {}
        subjects: dict[str, str] = {}
        for name, target in TARGETS.items():
            status, health = request(target.base_url, "GET", "/api/health")
            if status != 200 or health.get("status") != "healthy":
                raise RuntimeError(f"tenant {name} is unhealthy: {status} {health}")
            tokens[name], subjects[name] = bootstrap_and_login(target, creds[name])
            program = seed(target, subjects[name])
            report["tenants"][name] = {"health": health, "program": program, "subject_id": subjects[name]}

        findings: dict[str, Any] = {}
        for name, target in TARGETS.items():
            status, finding = request(target.base_url, "GET", "/api/v1/findings/qualification-collision", token=tokens[name])
            if status != 200:
                raise RuntimeError(f"tenant {name} finding control failed: {status} {finding}")
            findings[name] = finding
        report["assertions"]["T01_colliding_findings_are_distinct"] = (
            findings["a"]["description"] == "VIGIL-QUAL-A-ONLY-CANARY"
            and findings["b"]["description"] == "VIGIL-QUAL-B-ONLY-CANARY"
            and findings["a"]["description"] != findings["b"]["description"]
        )

        cross_status, _ = request(TARGETS["b"].base_url, "GET", "/api/v1/findings/qualification-collision", token=tokens["a"])
        spoof_status, _ = request(
            TARGETS["a"].base_url, "POST", "/api/v2/agent-runs",
            {"workflow_id": "triage-v1", "finding_ids": ["qualification-collision"], "prompt": "qualification"},
            token=tokens["a"], headers={"X-Tenant-ID": TARGETS["b"].tenant_id},
        )
        report["assertions"]["T05_foreign_token_denied"] = cross_status in {401, 403}
        report["assertions"]["T05_tenant_header_spoof_denied"] = spoof_status in {403, 404}

        for name, target in TARGETS.items():
            status, admitted = request(
                target.base_url, "POST", "/api/v2/agent-runs",
                {"workflow_id": "triage-v1", "finding_ids": ["qualification-collision"], "prompt": f"Investigate tenant {name} qualification canary"},
                token=tokens[name],
            )
            if status != 202:
                raise RuntimeError(f"tenant {name} admission failed: {status} {admitted}")
            final = wait_run(target, tokens[name], admitted["run_id"])
            report["tenants"][name]["managed_run"] = {"admission": admitted, "final": final}
            report["assertions"][f"T02_T03_tenant_{name}_managed_investigation_completed"] = final["status"] == "succeeded"
            report["tenants"][name]["worker_database_boundary"] = worker_database_boundary(name)

        if not all(bool(value) for value in report["assertions"].values()):
            raise RuntimeError("one or more qualification assertions failed")
        report["result"] = "passed"
        return 0
    except Exception as exc:
        report["result"] = "failed"
        report["error"] = str(exc)
        return 1
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        (EVIDENCE / "runtime.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        stop_forwards(forwards)
        print(json.dumps({"result": report.get("result"), "evidence": str(EVIDENCE / "runtime.json"), "assertions": report.get("assertions", {})}, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
