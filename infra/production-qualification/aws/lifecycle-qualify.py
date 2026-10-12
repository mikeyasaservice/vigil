#!/usr/bin/env python3
"""Qualify durable managed lifecycle, two-person approval, and registry tombstones."""

from __future__ import annotations

import importlib.util
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(os.getenv("VIGIL_AWS_QUALIFICATION_ROOT", "/tmp/vigil-aws-qualification"))
RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
EVIDENCE = ROOT / "evidence" / RUN_ID
CREDS = ROOT / "qualification-credentials.json"


def load_runtime() -> ModuleType:
    path = Path(__file__).with_name("runtime-qualify.py")
    spec = importlib.util.spec_from_file_location("vigil_runtime_qualify", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("runtime qualification helpers are unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runtime = load_runtime()


def backend_python(name: str, script: str, values: dict[str, str]) -> dict[str, Any]:
    args = ["exec", "-i", "-n", "vigil", "deploy/vigil-backend", "-c", "backend", "--", "env"]
    args += [f"{key}={value}" for key, value in values.items()]
    args += ["python", "-"]
    result = runtime.kubectl(name, *args, input_text=script)
    return json.loads(result.stdout.strip().splitlines()[-1])


def approver_credentials() -> dict[str, str]:
    held = json.loads(CREDS.read_text())
    approvers = held.setdefault("approvers", {})
    if "a" not in approvers:
        approvers["a"] = {
            "username": "qual_approver_a",
            "email": "qual-approver-a@example.com",
            "password": "Qv7!" + secrets.token_urlsafe(30) + "aA1!",
        }
        CREDS.write_text(json.dumps(held, indent=2) + "\n")
        CREDS.chmod(0o600)
    return approvers["a"]


def login(target: Any, credential: dict[str, str]) -> tuple[str, str]:
    status, body = runtime.request(
        target.base_url, "POST", "/api/auth/login",
        {"username_or_email": credential["username"], "password": credential["password"]},
    )
    if status != 200:
        raise RuntimeError(f"approver login failed: {status} {body}")
    return str(body["access_token"]), str(body["user"]["user_id"])


def ensure_approver(target: Any, admin_token: str, credential: dict[str, str]) -> tuple[str, str]:
    status, body = runtime.request(
        target.base_url, "POST", "/api/users/",
        {**credential, "full_name": "Qualification approver A", "role_id": "role-admin"},
        token=admin_token,
    )
    if status not in {201, 400}:
        raise RuntimeError(f"approver creation failed: {status} {body}")
    return login(target, credential)


MEMBERSHIP = r'''
import json, os
from sqlalchemy import text
from core.storage.connection import get_db_session, init_database
init_database(create_tables=False)
with get_db_session() as session:
    issuer=os.environ["VIGIL_AUTH_ISSUER"]
    session.execute(text("""
      DELETE FROM managed_memberships
      WHERE tenant_id=:tenant AND subject_id=:subject AND issuer<>:issuer
    """), {"tenant":os.environ["QUAL_TENANT"], "subject":os.environ["QUAL_SUBJECT"], "issuer":issuer})
    session.execute(text("""
      INSERT INTO managed_memberships (tenant_id, subject_id, issuer, roles, membership_version, status)
      VALUES (:tenant, :subject, :issuer, '["approver"]'::jsonb, 1, 'active')
      ON CONFLICT (tenant_id, subject_id, issuer) DO UPDATE SET roles='["approver"]'::jsonb,
        membership_version=managed_memberships.membership_version + 1, status='active'
    """), {"tenant":os.environ["QUAL_TENANT"], "subject":os.environ["QUAL_SUBJECT"], "issuer":issuer})
    session.commit()
print(json.dumps({"membership":"active"}))
'''


PENDING_APPROVAL = r'''
import json, os
from sqlalchemy import text
from core.storage.connection import get_db_session, init_database
init_database(create_tables=False)
with get_db_session() as session:
    execution = session.execute(text("SELECT execution_id FROM managed_runs WHERE run_id=CAST(:run AS uuid)"), {"run":os.environ["QUAL_RUN"]}).scalar_one()
    session.execute(text("UPDATE managed_runs SET status='waiting_approval', updated_at=now() WHERE run_id=CAST(:run AS uuid)"), {"run":os.environ["QUAL_RUN"]})
    session.execute(text("UPDATE managed_admissions SET status='active' WHERE execution_id=:execution"), {"execution":execution})
    session.execute(text("""
      INSERT INTO managed_approval_requests
        (execution_id, checkpoint_id, action, resource, argument_digest, policy_version, status)
      SELECT :execution, :checkpoint, :action, :resource, :digest, policy_version, 'pending'
      FROM managed_admissions WHERE execution_id=:execution
      ON CONFLICT (execution_id, checkpoint_id) DO UPDATE SET
        action=EXCLUDED.action, resource=EXCLUDED.resource, argument_digest=EXCLUDED.argument_digest,
        policy_version=EXCLUDED.policy_version, status='pending', resolved_at=NULL
    """), {"execution":execution, "checkpoint":os.environ["QUAL_CHECKPOINT"], "action":os.environ["QUAL_ACTION"],
             "resource":os.environ["QUAL_RESOURCE"], "digest":os.environ["QUAL_DIGEST"]})
    session.commit()
print(json.dumps({"execution_id":str(execution), "status":"waiting_approval"}))
'''


APPROVAL_STATE = r'''
import json, os
from sqlalchemy import text
from core.storage.connection import get_db_session, init_database
init_database(create_tables=False)
with get_db_session() as session:
    row=session.execute(text("""
      SELECT r.status, a.approver_subject_id, a.action, a.resource, a.argument_digest,
             q.status AS request_status
      FROM managed_runs r JOIN managed_approval_requests q ON q.execution_id=r.execution_id
      JOIN managed_approvals a ON a.execution_id=q.execution_id AND a.checkpoint_id=q.checkpoint_id
      WHERE r.run_id=CAST(:run AS uuid) AND q.checkpoint_id=:checkpoint
    """), {"run":os.environ["QUAL_RUN"], "checkpoint":os.environ["QUAL_CHECKPOINT"]}).mappings().one()
print(json.dumps(dict(row), default=str))
'''


FAIL_FOR_RESUME = r'''
import json, os
from sqlalchemy import text
from core.storage.connection import get_db_session, init_database
init_database(create_tables=False)
with get_db_session() as session:
    before=session.execute(text("SELECT envelope->'admission'->>'program_digest' FROM managed_runs WHERE run_id=CAST(:run AS uuid)"), {"run":os.environ["QUAL_RUN"]}).scalar_one()
    terminal=session.execute(text("SELECT count(*) FROM agent_events WHERE run_id=CAST(:run AS uuid) AND kind='terminal'"), {"run":os.environ["QUAL_RUN"]}).scalar_one()
    session.execute(text("UPDATE managed_runs SET status='failed', updated_at=now() WHERE run_id=CAST(:run AS uuid)"), {"run":os.environ["QUAL_RUN"]})
    session.commit()
print(json.dumps({"program_digest":before, "terminal_events":terminal, "status":"failed"}))
'''


INTERRUPTIBLE_STATE = r'''
import json, os, time
from sqlalchemy import text
from core.storage.connection import get_db_session, init_database
init_database(create_tables=False)
deadline=time.monotonic()+45
while time.monotonic() < deadline:
    with get_db_session() as session:
        row=session.execute(text("""
          SELECT r.status,
            (SELECT count(*) FROM agent_events e WHERE e.run_id=r.run_id) AS ledger_events,
            (SELECT count(*) FROM agent_events e WHERE e.run_id=r.run_id AND e.kind='terminal') AS terminal_events
          FROM managed_runs r WHERE r.run_id=CAST(:run AS uuid)
        """), {"run":os.environ["QUAL_RUN"]}).mappings().one()
    # The security repository deliberately persists the worker's transient
    # `retrying` report as `running` while it fences that failed claim. Recovery
    # therefore waits on the durable contract plus real ledger evidence.
    if row["status"] == "running" and row["ledger_events"] > 0 and row["terminal_events"] == 0:
        print(json.dumps(dict(row), default=str))
        break
    time.sleep(.1)
else:
    raise RuntimeError("managed run did not reach a ledger-backed retrying state")
'''


RESUME_STATE = r'''
import json, os
from sqlalchemy import text
from core.storage.connection import get_db_session, init_database
init_database(create_tables=False)
with get_db_session() as session:
    row=session.execute(text("""
      SELECT status, envelope->'admission'->>'program_digest' AS program_digest,
        (SELECT count(*) FROM managed_outbox o WHERE o.aggregate_id=r.execution_id AND o.event_type='managed.run.resumed') AS resume_events
      FROM managed_runs r WHERE run_id=CAST(:run AS uuid)
    """), {"run":os.environ["QUAL_RUN"]}).mappings().one()
print(json.dumps(dict(row), default=str))
'''


CANCEL_STATE = r'''
import json, os
from sqlalchemy import text
from core.storage.connection import get_db_session, init_database
init_database(create_tables=False)
with get_db_session() as session:
    row=session.execute(text("""
      SELECT r.status AS run_status, a.status AS admission_status, COALESCE(c.status,'absent') AS claim_status,
        (SELECT count(*) FROM managed_outbox o WHERE o.aggregate_id=r.execution_id AND o.event_type='managed.run.cancelled') AS cancel_events
      FROM managed_runs r JOIN managed_admissions a ON a.execution_id=r.execution_id
      LEFT JOIN managed_execution_claims c ON c.execution_id=r.execution_id
      WHERE r.run_id=CAST(:run AS uuid)
    """), {"run":os.environ["QUAL_RUN"]}).mappings().one()
print(json.dumps(dict(row), default=str))
'''


REGISTRY_TOMBSTONE = r'''
import json, os
from sqlalchemy import text
from core.storage.connection import get_db_session, init_database
init_database(create_tables=False)
tenant=os.environ["QUAL_TENANT"]
program="qualification-tombstone-"+os.environ["QUAL_SUFFIX"]
digest="sha256:"+("7"*64)
reactivation_denied=deletion_denied=False
with get_db_session() as session:
    session.execute(text("""
      INSERT INTO managed_program_registry
        (tenant_id, program_id, program_digest, artifact_signature, model_config_digest,
         dependency_digest, status, approved_by)
      VALUES (:tenant,:program,:digest,'qualification','sha256:model','sha256:deps','approved','qualification')
    """), {"tenant":tenant,"program":program,"digest":digest})
    session.execute(text("UPDATE managed_program_registry SET status='active', activated_at=now() WHERE tenant_id=:tenant AND program_id=:program"), {"tenant":tenant,"program":program})
    session.execute(text("UPDATE managed_program_registry SET status='revoked', revoked_at=now() WHERE tenant_id=:tenant AND program_id=:program"), {"tenant":tenant,"program":program})
    session.commit()
try:
    with get_db_session() as session:
        session.execute(text("UPDATE managed_program_registry SET status='active', revoked_at=NULL WHERE tenant_id=:tenant AND program_id=:program"), {"tenant":tenant,"program":program})
        session.commit()
except Exception:
    reactivation_denied=True
try:
    with get_db_session() as session:
        session.execute(text("DELETE FROM managed_program_registry WHERE tenant_id=:tenant AND program_id=:program"), {"tenant":tenant,"program":program})
        session.commit()
except Exception:
    deletion_denied=True
with get_db_session() as session:
    status=session.execute(text("SELECT status FROM managed_program_registry WHERE tenant_id=:tenant AND program_id=:program"), {"tenant":tenant,"program":program}).scalar_one()
print(json.dumps({"program_id":program,"status":status,"reactivation_denied":reactivation_denied,"deletion_denied":deletion_denied}))
'''


def scale_deployment(name: str, deployment: str, replicas: int, selector: str) -> None:
    result = runtime.kubectl(name, "scale", f"deployment/{deployment}", "-n", "vigil", f"--replicas={replicas}", check=False)
    if result.returncode:
        raise RuntimeError(f"{deployment} scale failed: {result.stderr.strip()}")
    if replicas:
        runtime.kubectl(name, "rollout", "status", f"deployment/{deployment}", "-n", "vigil", "--timeout=180s")
    else:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            pods = runtime.kubectl(name, "get", "pods", "-n", "vigil", "-l", selector, "-o", "name")
            if not pods.stdout.strip():
                return
            time.sleep(2)
        raise RuntimeError(f"{deployment} did not scale to zero")


def scale_worker(name: str, replicas: int) -> None:
    scale_deployment(name, "vigil-agent-worker", replicas, "app.kubernetes.io/component=agent-worker")


def scale_reasoner(name: str, replicas: int) -> None:
    scale_deployment(name, "vigil-reasoner", replicas, "app.kubernetes.io/component=reasoner")


def start_run(target: Any, token: str, prompt: str) -> dict[str, Any]:
    status, body = runtime.request(
        target.base_url, "POST", "/api/v2/agent-runs",
        {"workflow_id":"triage-v1", "finding_ids":["qualification-collision"], "prompt":prompt}, token=token,
    )
    if status != 202:
        raise RuntimeError(f"managed admission failed: {status} {body}")
    return body


def main() -> int:
    EVIDENCE.mkdir(parents=True, mode=0o700)
    report: dict[str, Any] = {"run_id":RUN_ID, "started_at":datetime.now(timezone.utc).isoformat(), "assertions":{}, "evidence":{}}
    forwards: list[Any] = []
    worker_scaled = False
    reasoner_scaled = False
    try:
        forwards = runtime.start_forwards()
        base_credentials = runtime.credentials()
        tokens: dict[str, str] = {}
        subjects: dict[str, str] = {}
        for name in ("a", "b"):
            tokens[name], subjects[name] = runtime.bootstrap_and_login(runtime.TARGETS[name], base_credentials[name])

        target = runtime.TARGETS["a"]
        approver_token, approver_subject = ensure_approver(target, tokens["a"], approver_credentials())
        backend_python("a", MEMBERSHIP, {"QUAL_TENANT":target.tenant_id, "QUAL_SUBJECT":approver_subject})

        approval_run = start_run(target, tokens["a"], "two-person approval qualification")
        runtime.wait_run(target, tokens["a"], approval_run["run_id"])
        checkpoint, action, resource = "qual-checkpoint", "synthetic_containment", "sink://qualification/a"
        argument_digest = "sha256:" + ("a" * 64)
        backend_python("a", PENDING_APPROVAL, {
            "QUAL_RUN":approval_run["run_id"], "QUAL_CHECKPOINT":checkpoint, "QUAL_ACTION":action,
            "QUAL_RESOURCE":resource, "QUAL_DIGEST":argument_digest,
        })
        approval_body = {"checkpoint_id":checkpoint, "action":action, "resource":resource, "argument_digest":argument_digest}
        owner_status, _ = runtime.request(target.base_url, "POST", f"/api/v2/agent-runs/{approval_run['run_id']}/approve", approval_body, token=tokens["a"])
        altered_status, _ = runtime.request(target.base_url, "POST", f"/api/v2/agent-runs/{approval_run['run_id']}/approve", {**approval_body,"resource":"sink://qualification/altered"}, token=approver_token)
        approved_status, approved = runtime.request(target.base_url, "POST", f"/api/v2/agent-runs/{approval_run['run_id']}/approve", approval_body, token=approver_token)
        report["evidence"]["approval_responses"] = {"run_id":approval_run["run_id"], "owner_status":owner_status, "altered_status":altered_status, "approved_status":approved_status}
        if approved_status != 200:
            raise RuntimeError(f"two-person approval failed: {approved_status} {approved}")
        approval_state = backend_python("a", APPROVAL_STATE, {"QUAL_RUN":approval_run["run_id"], "QUAL_CHECKPOINT":checkpoint})
        approval_ok = (
            owner_status == 403 and altered_status == 409 and approved_status == 200
            and approved["status"] == "approved" and approval_state["approver_subject_id"] == approver_subject
            and approval_state["approver_subject_id"] != subjects["a"] and approval_state["resource"] == resource
        )
        report["assertions"]["T06_two_person_bound_approval"] = approval_ok
        report["evidence"]["approval"] = {"run_id":approval_run["run_id"], "owner_status":owner_status, "altered_status":altered_status, "approved_status":approved_status, "state":approval_state}

        # Force a real transient failure after the worker has opened the durable
        # ledger, then stop the worker during BullMQ's retry backoff. This models
        # a process loss without inventing a ledger shape that execution never wrote.
        scale_reasoner("a", 0)
        reasoner_scaled = True
        resume_run = start_run(target, tokens["a"], "resume pin qualification")
        interrupted = backend_python("a", INTERRUPTIBLE_STATE, {"QUAL_RUN":resume_run["run_id"]})
        scale_worker("a", 0)
        worker_scaled = True
        scale_reasoner("a", 1)
        reasoner_scaled = False
        failed = backend_python("a", FAIL_FOR_RESUME, {"QUAL_RUN":resume_run["run_id"]})
        resume_status, resume_response = runtime.request(target.base_url, "POST", f"/api/v2/agent-runs/{resume_run['run_id']}/resume", token=tokens["a"])
        resumed = backend_python("a", RESUME_STATE, {"QUAL_RUN":resume_run["run_id"]})
        scale_worker("a", 1)
        worker_scaled = False
        resume_final = runtime.wait_run(target, tokens["a"], resume_run["run_id"])
        resume_ok = (
            failed["terminal_events"] == 0 and resume_status == 202 and resumed["resume_events"] == 1
            and resumed["program_digest"] == failed["program_digest"] and resume_response["execution_id"] == resume_run["execution_id"]
            and resume_final["status"] == "succeeded"
        )
        report["assertions"]["T04_T13_resume_is_idempotent_and_program_pinned"] = resume_ok
        report["evidence"]["resume"] = {
            "run_id":resume_run["run_id"], "interrupted":interrupted,
            "before":failed, "after":resumed, "final":resume_final,
        }

        cancel_status, cancelled = runtime.request(target.base_url, "POST", f"/api/v2/agent-runs/{resume_run['run_id']}/cancel", token=tokens["a"])
        runtime.kubectl("a", "rollout", "restart", "deployment/vigil-security", "-n", "vigil")
        runtime.kubectl("a", "rollout", "status", "deployment/vigil-security", "-n", "vigil", "--timeout=180s")
        post_restart_status, post_restart = runtime.request(target.base_url, "GET", f"/api/v2/agent-runs/{resume_run['run_id']}", token=tokens["a"])
        denied_resume_status, _ = runtime.request(target.base_url, "POST", f"/api/v2/agent-runs/{resume_run['run_id']}/resume", token=tokens["a"])
        cancel_state = backend_python("a", CANCEL_STATE, {"QUAL_RUN":resume_run["run_id"]})
        cancel_ok = (
            cancel_status == 200 and cancelled["status"] == "cancelled" and post_restart_status == 200
            and post_restart["status"] == "cancelled" and denied_resume_status == 409
            and cancel_state["admission_status"] == "revoked" and cancel_state["claim_status"] == "cancelled"
            and cancel_state["cancel_events"] == 1
        )
        report["assertions"]["T10_cancellation_survives_gateway_restart"] = cancel_ok
        report["evidence"]["cancellation"] = {"run_id":resume_run["run_id"], "resume_denial_status":denied_resume_status, "state":cancel_state}

        tombstone = backend_python("a", REGISTRY_TOMBSTONE, {"QUAL_TENANT":target.tenant_id, "QUAL_SUFFIX":RUN_ID.lower()})
        tombstone_ok = tombstone["status"] == "revoked" and tombstone["reactivation_denied"] and tombstone["deletion_denied"]
        report["assertions"]["T13_revoked_program_tombstone_is_irreversible"] = tombstone_ok
        report["evidence"]["registry"] = tombstone

        b_run = start_run(runtime.TARGETS["b"], tokens["b"], "peer availability after tenant A lifecycle faults")
        b_final = runtime.wait_run(runtime.TARGETS["b"], tokens["b"], b_run["run_id"])
        report["assertions"]["T12_tenant_b_survives_tenant_a_lifecycle_faults"] = b_final["status"] == "succeeded"
        report["evidence"]["tenant_b_control"] = b_final

        report["result"] = "passed" if all(report["assertions"].values()) else "failed"
        return 0 if report["result"] == "passed" else 1
    except Exception as exc:
        report["result"] = "failed"
        report["error"] = str(exc)
        return 1
    finally:
        if reasoner_scaled:
            try:
                scale_reasoner("a", 1)
            except Exception as exc:
                report["reasoner_restore_error"] = str(exc)
                report["result"] = "failed"
        if worker_scaled:
            try:
                scale_worker("a", 1)
            except Exception as exc:
                report["worker_restore_error"] = str(exc)
                report["result"] = "failed"
        if forwards:
            runtime.stop_forwards(forwards)
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        path = EVIDENCE / "lifecycle.json"
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"result":report.get("result"), "evidence":str(path), "assertions":report["assertions"]}, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
