#!/usr/bin/env python3
"""Run the expanded T01-T06/T14 isolation matrix in two deployed AWS tenants.

Every negative check has a working same-tenant control and an unchanged-state
observation. Raw identifiers and canaries remain in the mode-0700 evidence root.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("autobot_runtime_qualify", HERE / "runtime-qualify.py")
if spec is None or spec.loader is None:
    raise RuntimeError("runtime qualification helpers are unavailable")
runtime = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runtime
spec.loader.exec_module(runtime)

ROOT = runtime.ROOT
RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
EVIDENCE = ROOT / "evidence" / RUN_ID


MATRIX_SEED = r'''
import json, os
from sqlalchemy import text
from core.storage.connection import get_db_session, init_database

tenant=os.environ["QUAL_TENANT"]
canary=os.environ["QUAL_CANARY"]
suffix=os.environ["QUAL_SUFFIX"]
init_database(create_tables=False)
with get_db_session() as session:
    session.execute(text("""
      INSERT INTO cases (case_id,title,description,status,priority,tags,timeline)
      VALUES ('qualification-collision','Qualification collision',:canary,'open','high',
              ARRAY[:tenant], CAST(:timeline AS jsonb))
      ON CONFLICT (case_id) DO UPDATE SET description=EXCLUDED.description,
        tags=EXCLUDED.tags,timeline=EXCLUDED.timeline,updated_at=now()
    """), {"canary":canary,"tenant":tenant,"timeline":json.dumps([{"canary":canary}])})
    session.execute(text("""
      INSERT INTO cases (case_id,title,description,status,priority,tags,timeline)
      VALUES ('qualification-delete-control','Qualification delete control',:canary,
              'open','low',ARRAY[:tenant],'[]'::jsonb)
      ON CONFLICT (case_id) DO UPDATE SET description=EXCLUDED.description,
        status='open',updated_at=now()
    """), {"canary":canary,"tenant":tenant})
    session.execute(text("DELETE FROM case_comments WHERE case_id='qualification-collision'"))
    session.execute(text("DELETE FROM case_evidence WHERE case_id='qualification-collision'"))
    session.execute(text("DELETE FROM case_attachments WHERE case_id='qualification-collision'"))
    session.execute(text("DELETE FROM case_iocs WHERE case_id='qualification-collision'"))
    session.execute(text("""
      INSERT INTO case_comments(case_id,author,content,is_edited,is_deleted)
      VALUES ('qualification-collision',:tenant,:canary,false,false);
      INSERT INTO case_evidence(case_id,evidence_type,name,description,source,collected_by,
        collected_at,chain_of_custody,tags)
      VALUES ('qualification-collision','log',:canary,:canary,:tenant,:tenant,now(),'[]'::jsonb,ARRAY[:tenant]);
      INSERT INTO case_attachments(case_id,filename,file_path,file_type,file_size,mime_type,
        uploaded_by,description,tags,virus_scan_result)
      VALUES ('qualification-collision',:filename,:path,'text',length(:canary),'text/plain',
        :tenant,:canary,ARRAY[:tenant],'clean');
      INSERT INTO case_iocs(case_id,ioc_type,value,threat_level,confidence,source,tags,
        context,is_active,is_false_positive)
      VALUES ('qualification-collision','domain',:ioc,'high',1.0,:tenant,ARRAY[:tenant],
        :canary,true,false)
    """), {"tenant":tenant,"canary":canary,"filename":f"{suffix}-evidence.txt",
             "path":f"s3://tenant-{suffix}-qualification/evidence/{suffix}.txt",
             "ioc":f"{suffix}.qualification.invalid"})
    session.execute(text("DELETE FROM episodic_sightings WHERE investigation_id='qualification-memory'"))
    session.execute(text("""
      INSERT INTO episodic_sightings(entity_key,investigation_kind,investigation_id,
        source_system,hit_count,attacker_influenceable,first_seen,last_seen,concluded_at)
      VALUES ('host:qualification-collision','case','qualification-memory',:canary,1,false,
        now(),now(),now())
    """), {"canary":canary})
    session.execute(text("DELETE FROM llm_interaction_logs WHERE interaction_id='qualification-model-history'"))
    session.execute(text("""
      INSERT INTO llm_interaction_logs(interaction_id,session_id,agent_id,investigation_id,
        model,request_messages,system_prompt,thinking_enabled,response_content,tool_calls,
        tool_results,input_tokens,output_tokens,cache_read_tokens,cache_creation_tokens,duration_ms)
      VALUES ('qualification-model-history',:tenant,'managed-triage','qualification-history',
        'deterministic-qualification',CAST(:messages AS jsonb),:canary,false,:canary,
        '[]'::jsonb,'[]'::jsonb,1,1,0,0,1)
    """), {"tenant":tenant,"canary":canary,
             "messages":json.dumps([{"role":"user","content":canary}])})
    session.commit()
with get_db_session() as session:
    counts=session.execute(text("""
      SELECT
        (SELECT count(*) FROM cases WHERE case_id='qualification-collision') cases,
        (SELECT count(*) FROM case_evidence WHERE case_id='qualification-collision') evidence,
        (SELECT count(*) FROM case_attachments WHERE case_id='qualification-collision') attachments,
        (SELECT count(*) FROM episodic_sightings WHERE investigation_id='qualification-memory') memory,
        (SELECT count(*) FROM llm_interaction_logs WHERE interaction_id='qualification-model-history') history
    """)).mappings().one()
print(json.dumps(dict(counts)))
'''


DB_STATE = r'''
import json, os
from sqlalchemy import text
from core.storage.connection import get_db_session, init_database
init_database(create_tables=False)
with get_db_session() as session:
  row=session.execute(text("""
    SELECT
      (SELECT md5(string_agg(case_id||coalesce(description,''),',' ORDER BY case_id)) FROM cases) cases,
      (SELECT md5(string_agg(comment_id::text||coalesce(content,''),',' ORDER BY comment_id)) FROM case_comments) comments,
      (SELECT md5(string_agg(evidence_id::text||coalesce(description,''),',' ORDER BY evidence_id)) FROM case_evidence) evidence,
      (SELECT md5(string_agg(attachment_id::text||filename,',' ORDER BY attachment_id)) FROM case_attachments) attachments,
      (SELECT md5(string_agg(ioc_id::text||value||coalesce(context,''),',' ORDER BY ioc_id)) FROM case_iocs) iocs,
      (SELECT md5(string_agg(id::text||source_system,',' ORDER BY id)) FROM episodic_sightings) memory,
      (SELECT md5(string_agg(id::text||coalesce(response_content,''),',' ORDER BY id)) FROM llm_interaction_logs) history,
      (SELECT count(*) FROM managed_invocation_reservations) connector_effects
  """)).mappings().one()
print(json.dumps(dict(row)))
'''


CACHE_PROBE = r'''
import Redis from "ioredis";
const url=new URL(process.env.REDIS_URL||"redis://localhost:6379/0");
const options=process.env.REDIS_HOST?{
  host:process.env.REDIS_HOST,port:Number(process.env.REDIS_PORT||6379),
  db:Number(process.env.REDIS_DB||0),password:process.env.REDIS_PASSWORD||undefined,
  maxRetriesPerRequest:2,
}:{
  host:url.hostname,port:Number(url.port||6379),db:Number(url.pathname.slice(1)||0),
  username:url.username?decodeURIComponent(url.username):undefined,
  password:url.password?decodeURIComponent(url.password):undefined,
  tls:url.protocol==="rediss:"?{}:undefined,maxRetriesPerRequest:2,
};
const redis=new Redis(options);
await redis.set("autobot:qualification:collision",process.env.QUAL_CANARY,"EX",600);
const value=await redis.get("autobot:qualification:collision");
const failed=Number(await redis.zcard("{bull}:agent-runs:failed"));
await redis.quit();
console.log(JSON.stringify({value,failed}));
'''


FOREIGN_TCP_PROBE = r'''
import net from "node:net";
const result=await new Promise((resolve)=>{
  const socket=net.createConnection({host:process.env.QUAL_HOST,port:6379});
  const finish=(value)=>{socket.destroy();resolve(value)};
  socket.setTimeout(3000,()=>finish({connected:false,reason:"timeout"}));
  socket.once("connect",()=>finish({connected:true,reason:"connected"}));
  socket.once("error",error=>finish({connected:false,reason:error.code||"error"}));
});
console.log(JSON.stringify(result));
'''


REPLAY_ENQUEUE = r'''
import asyncio, copy, json, os, uuid
from sqlalchemy import text
from core.agents.queue import build_start_job, close_run_queue, enqueue_run
from core.storage.connection import get_db_session, init_database
run=os.environ["QUAL_RUN"]
init_database(create_tables=False)
with get_db_session() as session:
  row=session.execute(text("""
    SELECT r.run_kind,r.request,r.envelope,r.subject_id,
      (SELECT count(*) FROM agent_events e WHERE e.run_id=r.run_id) events,
      (SELECT count(*) FROM managed_invocation_reservations i WHERE i.execution_id=r.execution_id) effects
    FROM managed_runs r WHERE r.run_id=CAST(:run AS uuid)
  """),{"run":run}).mappings().one()
job=build_start_job(run_id=run,run_kind=row["run_kind"],request=row["request"],
  enqueued_by=row["subject_id"],managed_envelope=row["envelope"])
tampered=copy.deepcopy(job)
tampered["managed"]["references"]["program_digest"]="sha256:"+("0"*64)
async def main():
  replay=await enqueue_run(job,job_id="qualification-replay-"+str(uuid.uuid4()))
  forged=await enqueue_run(tampered,job_id="qualification-forged-"+str(uuid.uuid4()))
  await close_run_queue()
  return {"replay_job":replay,"forged_job":forged,"events":row["events"],"effects":row["effects"]}
print(json.dumps(asyncio.run(main())))
'''


RUN_EFFECTS = r'''
import json, os
from sqlalchemy import text
from core.storage.connection import get_db_session, init_database
run=os.environ["QUAL_RUN"]
init_database(create_tables=False)
with get_db_session() as session:
  row=session.execute(text("""
    SELECT r.status,
      (SELECT count(*) FROM agent_events e WHERE e.run_id=r.run_id) events,
      (SELECT count(*) FROM managed_invocation_reservations i WHERE i.execution_id=r.execution_id) effects
    FROM managed_runs r WHERE r.run_id=CAST(:run AS uuid)
  """),{"run":run}).mappings().one()
print(json.dumps(dict(row)))
'''


AUTH_VARIANTS = r'''
import json, os, time, uuid, jwt
from sqlalchemy import text
from core.auth.auth_service import JWT_ALGORITHM, JWT_SECRET_KEY
from core.storage.connection import get_db_session, init_database
init_database(create_tables=False)
subject=os.environ["QUAL_SUBJECT"]
with get_db_session() as session:
  user=session.execute(text("SELECT user_id,username,email,role_id FROM users WHERE user_id=CAST(:subject AS uuid)"),{"subject":subject}).mappings().one()
now=int(time.time())
base={"user_id":str(user["user_id"]),"username":user["username"],"email":user["email"],
  "role_id":str(user["role_id"]),"token_type":"access","jti":uuid.uuid4().hex,
  "iat":now,"exp":now+300,"iss":os.environ["VIGIL_AUTH_ISSUER"],"aud":os.environ["VIGIL_AUTH_AUDIENCE"]}
def token(**changes): return jwt.encode({**base,**changes},JWT_SECRET_KEY,algorithm=JWT_ALGORITHM)
print(json.dumps({"expired":token(exp=now-1),"wrong_issuer":token(iss="https://foreign.invalid"),
  "wrong_audience":token(aud="foreign-audience")}))
'''


MEMBERSHIP_STATUS = r'''
import json, os
from sqlalchemy import text
from core.storage.connection import get_db_session, init_database
init_database(create_tables=False)
with get_db_session() as session:
  session.execute(text("UPDATE managed_memberships SET status=:status WHERE tenant_id=:tenant AND subject_id=:subject"),
    {"status":os.environ["QUAL_STATUS"],"tenant":os.environ["QUAL_TENANT"],"subject":os.environ["QUAL_SUBJECT"]})
  session.commit()
print(json.dumps({"updated":True}))
'''


RUN_ENVELOPE = r'''
import json, os
from sqlalchemy import text
from core.storage.connection import get_db_session, init_database
init_database(create_tables=False)
with get_db_session() as session:
  row=session.execute(text("SELECT envelope,execution_id FROM managed_runs WHERE run_id=CAST(:run AS uuid)"),
    {"run":os.environ["QUAL_RUN"]}).mappings().one()
print(json.dumps({"envelope":row["envelope"],"execution_id":str(row["execution_id"])}))
'''


GRANT_MATRIX = r'''
import { randomUUID } from "node:crypto";
const gateway="http://127.0.0.1:15001/v1";
const envelope=JSON.parse(process.env.QUAL_ENVELOPE);
const post=async(path,body,headers={})=>{
  const response=await fetch(gateway+path,{method:"POST",headers:{"content-type":"application/json",...headers},body:JSON.stringify(body)});
  let value=null; try { value=await response.json(); } catch {}
  return {status:response.status,value};
};
const claimed=await post("/claim",{envelope,capabilities:["get_finding","recall_entity"]});
if(claimed.status!==200) throw new Error(`claim failed ${claimed.status}`);
const identity=claimed.value;
const args={finding_id:"qualification-collision"};
const bound={execution_id:identity.execution_id,tenant_id:identity.tenant_id,
  deployment_id:identity.deployment_id,worker_key_id:identity.worker_key_id,
  claim_token:identity.jti,attestation:identity.attestation,tool:"get_finding",args,
  max_rows:1,timeout_ms:10000};
const issued=await post("/grants",bound);
if(issued.status!==200) throw new Error(`grant failed ${issued.status}`);
const grant=issued.value;
const invoke=async(bodyGrant,bodyChanges={})=>post("/authorize",{...bound,...bodyChanges,grant:bodyGrant},
  {"x-vigil-invocation-id":randomUUID()});
const positive=await invoke(grant);
const memoryArgs={entity_keys:["host:qualification-collision"],as_of:new Date().toISOString()};
const memoryBound={...bound,tool:"recall_entity",args:memoryArgs,max_rows:1,timeout_ms:10000};
const memoryIssued=await post("/grants",memoryBound);
if(memoryIssued.status!==200) throw new Error(`memory grant failed ${memoryIssued.status}`);
const memoryPositive=await post("/authorize",{...memoryBound,grant:memoryIssued.value},
  {"x-vigil-invocation-id":randomUUID()});
const changes={execution_id:"00000000-0000-4000-8000-000000000099",tenant_id:"tenant-foreign",
  deployment_id:"deployment-foreign",deployment_incarnation:"99999999-9999-4999-8999-999999999999",
  workflow_id:"workflow-foreign",workflow_digest:"workflow-foreign-digest",
  program_id:"program-foreign",program_digest:"program-foreign-digest",
  action:"case_records",resource:"foreign",argument_digest:"0".repeat(64),
  policy_version:"policy-foreign",revocation_epoch:identity.revocation_epoch+1,
  workload_key_id:"spiffe://autobot.internal/ns/foreign/sa/worker",claim_jti:"foreign-claim",
  max_rows:2,timeout_ms:10001,expires_at:new Date(Date.now()-1000).toISOString()};
const denied={};
for(const [field,value] of Object.entries(changes)) denied[field]=(await invoke({...grant,[field]:value})).status;
denied.body_tenant=(await invoke(grant,{tenant_id:"tenant-foreign"})).status;
denied.body_execution=(await invoke(grant,{execution_id:"00000000-0000-4000-8000-000000000099"})).status;
denied.changed_args=(await invoke(grant,{args:{finding_id:"foreign"}})).status;
console.log(JSON.stringify({claim_status:claimed.status,grant_status:issued.status,
  positive_status:positive.status,positive_ok:positive.value?.ok===true,
  memory_status:memoryPositive.status,memory_ok:memoryPositive.value?.ok===true,
  memory_result:memoryPositive.value,denied}));
'''


def backend_python(name: str, program: str, env: dict[str, str]) -> dict[str, Any]:
    args = ["exec", "-i", "-n", "vigil", "deploy/vigil-backend", "-c", "backend", "--", "env"]
    args.extend(f"{key}={value}" for key, value in env.items())
    args.extend(["python", "-"])
    result = runtime.kubectl(name, *args, input_text=program)
    return json.loads(result.stdout.strip().splitlines()[-1])


def worker_node(name: str, program: str, env: dict[str, str]) -> dict[str, Any]:
    args = ["exec", "-n", "vigil", "deploy/vigil-agent-worker", "-c", "agent-worker", "--", "env"]
    args.extend(f"{key}={value}" for key, value in env.items())
    args.extend(["node", "--input-type=module", "-e", program])
    result = runtime.kubectl(name, *args)
    return json.loads(result.stdout.strip().splitlines()[-1])


def aws(name: str, *args: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["aws", *args], env=runtime.aws_env(name), input=input_bytes,
        capture_output=True, check=False,
    )


def outputs(name: str) -> dict[str, Any]:
    return json.loads((ROOT / f"tenant-{name}" / "outputs.json").read_text())


def body_contains(value: Any, expected: str) -> bool:
    return expected in json.dumps(value, sort_keys=True)


def main() -> int:
    EVIDENCE.mkdir(parents=True, exist_ok=True, mode=0o700)
    report: dict[str, Any] = {
        "run_id": RUN_ID,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "matrix": {}, "assertions": {}, "tenants": {},
    }
    forwards: list[subprocess.Popen[str]] = []
    try:
        forwards = runtime.start_forwards()
        credentials = runtime.credentials()
        tokens: dict[str, str] = {}
        canaries = {"a": "VIGIL-QUAL-A-ONLY-CANARY", "b": "VIGIL-QUAL-B-ONLY-CANARY"}
        for name, target in runtime.TARGETS.items():
            tokens[name], subject = runtime.bootstrap_and_login(target, credentials[name])
            program = runtime.seed(target, subject)
            seeded = backend_python(name, MATRIX_SEED, {
                "QUAL_TENANT": target.tenant_id, "QUAL_CANARY": canaries[name], "QUAL_SUFFIX": name,
            })
            state = backend_python(name, DB_STATE, {})
            cache = worker_node(name, CACHE_PROBE, {"QUAL_CANARY": canaries[name]})
            database_boundary = runtime.worker_database_boundary(name)
            report["tenants"][name] = {"subject": subject, "program": program, "seeded": seeded, "state_before": state, "cache": cache, "database_boundary": database_boundary}
            report["assertions"][f"T01_T03_T04_{name}_positive_controls"] = (
                all(int(seeded[key]) == 1 for key in ("cases", "evidence", "attachments", "memory", "history"))
                and cache["value"] == canaries[name]
            )
            report["assertions"][f"T14_{name}_runtime_database_bypass_denied"] = (
                database_boundary["db_user"] == "vigil_agent"
                and database_boundary["initial_search_path"].replace('"', '') == "pg_catalog, public"
                and all(database_boundary[key] for key in (
                    "protected_table_denied", "domain_table_denied", "join_denied",
                    "set_role_denied", "ddl_denied", "temp_denied",
                    "truncate_denied", "function_denied", "search_path_bypass_denied",
                    "recovered_after_failed_transaction",
                ))
            )

        paths = (
            ("finding_get", "/api/v1/findings/qualification-collision"),
            ("finding_search", "/api/v1/findings?search=qualification-collision&limit=1"),
            ("case_get", "/api/v1/cases/qualification-collision"),
            ("case_search", "/api/v1/cases?query=qualification-collision&limit=1"),
            ("evidence", "/api/v1/cases/qualification-collision/evidence"),
            ("comments", "/api/cases/qualification-collision/comments"),
            ("ioc_export", "/api/v1/cases/qualification-collision/iocs/export?format=json"),
            ("full_text_join", "/api/cases/search/full-text?query=VIGIL-QUAL&search_comments=true&search_evidence=true&limit=20"),
            ("ioc_join", "/api/cases/search/by-ioc?ioc_value={suffix}.qualification.invalid"),
            ("case_count", "/api/v1/cases/stats/summary"),
        )
        for name, target in runtime.TARGETS.items():
            other = "b" if name == "a" else "a"
            before_foreign = backend_python(other, DB_STATE, {})
            for label, path_template in paths:
                path = path_template.format(suffix=name)
                own_status, own_body = runtime.request(target.base_url, "GET", path, token=tokens[name])
                foreign_status, foreign_body = runtime.request(
                    runtime.TARGETS[other].base_url, "GET", path, token=tokens[name]
                )
                own_control = own_status == 200 and (
                    label == "case_count" or body_contains(own_body, canaries[name])
                )
                passed = (
                    own_control and foreign_status in {401, 403, 404}
                    and not body_contains(foreign_body, canaries[other])
                )
                report["matrix"][f"T01_{name}_{label}"] = {
                    "positive_status": own_status, "foreign_status": foreign_status,
                    "foreign_canary_absent": not body_contains(foreign_body, canaries[other]),
                }
                report["assertions"][f"T01_{name}_{label}"] = passed
            after_foreign = backend_python(other, DB_STATE, {})
            report["assertions"][f"T01_{name}_foreign_state_unchanged"] = before_foreign == after_foreign

        # Exercise mutation, relationship/join, bulk and delete routes with an
        # A/B token substitution. Each foreign denial is followed by a same-
        # tenant control and an unchanged peer digest.
        for name, target in runtime.TARGETS.items():
            other = "b" if name == "a" else "a"
            peer = runtime.TARGETS[other]
            before_peer = backend_python(other, DB_STATE, {})
            bulk_body = {"iocs": [{"ioc_type": "domain", "value": f"bulk-{name}.qualification.invalid",
                                     "threat_level": "low", "confidence": 0.5,
                                     "source": "qualification", "context": canaries[name]}]}
            foreign_bulk, _ = runtime.request(peer.base_url, "POST", "/api/v1/cases/qualification-collision/iocs/bulk", bulk_body, token=tokens[name])
            foreign_link, _ = runtime.request(peer.base_url, "POST", "/api/v1/cases/qualification-collision/findings/qualification-collision", {}, token=tokens[name])
            foreign_delete, _ = runtime.request(peer.base_url, "DELETE", "/api/cases/qualification-delete-control", token=tokens[name])
            after_peer = backend_python(other, DB_STATE, {})
            own_bulk, own_bulk_body = runtime.request(target.base_url, "POST", "/api/v1/cases/qualification-collision/iocs/bulk", bulk_body, token=tokens[name])
            own_link, own_link_body = runtime.request(target.base_url, "POST", "/api/v1/cases/qualification-collision/findings/qualification-collision", {}, token=tokens[name])
            own_delete, own_delete_body = runtime.request(target.base_url, "DELETE", "/api/cases/qualification-delete-control", token=tokens[name])
            report["matrix"][f"T01_{name}_mutations"] = {
                "foreign": {"bulk": foreign_bulk, "link": foreign_link, "delete": foreign_delete},
                "positive": {"bulk": own_bulk, "link": own_link, "delete": own_delete},
            }
            report["assertions"][f"T01_{name}_bulk_join_delete"] = (
                all(status in {401, 403, 404} for status in (foreign_bulk, foreign_link, foreign_delete))
                and before_peer == after_peer
                and own_bulk == 200 and int(own_bulk_body.get("added", 0)) == 1
                and own_link == 200 and body_contains(own_link_body, "qualification-collision")
                and own_delete == 200 and own_delete_body.get("success") is True
            )

        # Actual S3 bytes use the same key in both tenant buckets. The A/B workload
        # profiles must read their own object and be denied the other's bucket.
        key = "qualification/collision.txt"
        for name in ("a", "b"):
            bucket = outputs(name)["evidenceBucket"]
            source_path = EVIDENCE / f"{name}-object-source.txt"
            source_path.write_text(canaries[name])
            put = aws(name, "s3api", "put-object", "--bucket", bucket, "--key", key, "--body", str(source_path))
            own_path = EVIDENCE / f"{name}-object-control.txt"
            own = aws(name, "s3api", "get-object", "--bucket", bucket, "--key", key, str(own_path))
            other = "b" if name == "a" else "a"
            foreign_bucket = outputs(other)["evidenceBucket"]
            foreign_path = EVIDENCE / f"{name}-foreign-object.txt"
            foreign = aws(name, "s3api", "get-object", "--bucket", foreign_bucket, "--key", key, str(foreign_path))
            report["assertions"][f"T01_{name}_object_store"] = (
                put.returncode == 0 and own.returncode == 0 and own_path.read_text() == canaries[name]
                and foreign.returncode != 0
            )

        # The queue/cache control above proves the tenant-local endpoint works.
        # A TCP attempt from the real worker pod to the peer ElastiCache endpoint
        # must fail, and the peer value/failed set must remain unchanged.
        for name in ("a", "b"):
            other = "b" if name == "a" else "a"
            peer_before = worker_node(other, CACHE_PROBE, {"QUAL_CANARY": canaries[other]})
            tcp = worker_node(name, FOREIGN_TCP_PROBE, {"QUAL_HOST": outputs(other)["redisEndpoint"]})
            peer_after = worker_node(other, CACHE_PROBE, {"QUAL_CANARY": canaries[other]})
            report["matrix"][f"T04_{name}_peer_broker_network"] = tcp
            report["assertions"][f"T04_{name}_peer_broker_network_denied"] = (
                tcp["connected"] is False and peer_before == peer_after
            )

        # A managed investigation is the positive connector/DSPy/recall path.
        # Foreign requests above must leave B's connector reservation count stable.
        for name, target in runtime.TARGETS.items():
            status, started = runtime.request(
                target.base_url, "POST", "/api/v2/agent-runs",
                {"workflow_id": "triage-v1", "finding_ids": ["qualification-collision"],
                 "prompt": f"Investigate host:qualification-collision for {canaries[name]}"},
                token=tokens[name],
            )
            if status != 202:
                raise RuntimeError(f"tenant {name} managed positive failed: {status} {started}")
            final = runtime.wait_run(target, tokens[name], started["run_id"])
            after = backend_python(name, DB_STATE, {})
            report["tenants"][name]["managed_run"] = {"admission": started, "final": final, "state_after": after}
            report["assertions"][f"T02_T03_{name}_managed_positive"] = (
                final["status"] == "succeeded"
                and int(after["connector_effects"]) > int(report["tenants"][name]["state_before"]["connector_effects"])
            )

        # Hold the real consumer, claim through the worker's SPIFFE/mTLS proxy,
        # run one authorized connector read, then mutate every grant binding.
        # Only the positive call may create a reservation/effect.
        for name, target in runtime.TARGETS.items():
            runtime.kubectl(
                name, "exec", "-n", "vigil", "deploy/vigil-agent-worker",
                "-c", "agent-worker", "--", "node", "-e",
                "process.kill(1, 'SIGSTOP')",
            )
            probe_started: dict[str, Any] | None = None
            before = backend_python(name, DB_STATE, {})
            try:
                status, probe_started = runtime.request(
                    target.base_url, "POST", "/api/v2/agent-runs",
                    {"workflow_id": "triage-v1", "finding_ids": ["qualification-collision"], "prompt": "grant substitution matrix"},
                    token=tokens[name],
                )
                if status != 202:
                    raise RuntimeError(f"tenant {name} grant probe admission failed: {status} {probe_started}")
                held = backend_python(name, RUN_ENVELOPE, {"QUAL_RUN": probe_started["run_id"]})
                grant_matrix = worker_node(name, GRANT_MATRIX, {
                    "QUAL_ENVELOPE": json.dumps(held["envelope"], separators=(",", ":")),
                    "QUAL_CANARY": canaries[name],
                    "QUAL_FOREIGN_CANARY": canaries["b" if name == "a" else "a"],
                })
                after_probe = backend_python(name, DB_STATE, {})
            finally:
                runtime.kubectl(
                    name, "exec", "-n", "vigil", "deploy/vigil-agent-worker",
                    "-c", "agent-worker", "--", "node", "-e",
                    "process.kill(1, 'SIGCONT')", check=False,
                )
            if probe_started is None:
                raise RuntimeError("grant matrix did not create its positive control")
            runtime.wait_run(target, tokens[name], probe_started["run_id"])
            report["tenants"][name]["grant_matrix"] = grant_matrix
            report["assertions"][f"T06_{name}_full_grant_substitution_matrix"] = (
                grant_matrix["claim_status"] == 200 and grant_matrix["grant_status"] == 200
                and grant_matrix["positive_status"] == 200 and grant_matrix["positive_ok"]
                and grant_matrix["memory_status"] == 200 and grant_matrix["memory_ok"]
                and body_contains(grant_matrix["memory_result"], canaries[name])
                and not body_contains(grant_matrix["memory_result"], canaries["b" if name == "a" else "a"])
                and all(status in {401, 403, 422} for status in grant_matrix["denied"].values())
                and int(after_probe["connector_effects"]) == int(before["connector_effects"]) + 2
            )

        # Replaying completed exact work and a correctly shaped but altered
        # envelope both enter the real broker and must land in its failed set
        # without a ledger event or connector effect.
        for name in ("a", "b"):
            run_id = report["tenants"][name]["managed_run"]["admission"]["run_id"]
            cache_before = worker_node(name, CACHE_PROBE, {"QUAL_CANARY": canaries[name]})
            replay = backend_python(name, REPLAY_ENQUEUE, {"QUAL_RUN": run_id})
            time.sleep(35)
            cache_after = worker_node(name, CACHE_PROBE, {"QUAL_CANARY": canaries[name]})
            effects_after = backend_python(name, RUN_EFFECTS, {"QUAL_RUN": run_id})
            report["tenants"][name]["broker_replay"] = {
                "enqueued": replay, "cache_before": cache_before,
                "cache_after": cache_after, "effects_after": effects_after,
            }
            report["assertions"][f"T04_{name}_replay_and_forgery_zero_effect"] = (
                int(cache_after["failed"]) >= int(cache_before["failed"]) + 2
                and int(effects_after["events"]) == int(replay["events"])
                and int(effects_after["effects"]) == int(replay["effects"])
                and effects_after["status"] == "succeeded"
            )

        # Managed JWTs require issuer, audience and time validity. Membership is
        # re-read at admission, and logout revocation is checked on the next API call.
        for name, target in runtime.TARGETS.items():
            subject = report["tenants"][name]["subject"]
            variants = backend_python(name, AUTH_VARIANTS, {"QUAL_SUBJECT": subject})
            auth_denials: dict[str, int] = {}
            for label, token in variants.items():
                status, _ = runtime.request(target.base_url, "GET", "/api/v1/findings?limit=1", token=token)
                auth_denials[label] = status
            backend_python(name, MEMBERSHIP_STATUS, {
                "QUAL_TENANT": target.tenant_id, "QUAL_SUBJECT": subject, "QUAL_STATUS": "revoked",
            })
            revoked_status, _ = runtime.request(
                target.base_url, "POST", "/api/v2/agent-runs",
                {"workflow_id": "triage-v1", "finding_ids": ["qualification-collision"], "prompt": "revoked membership"},
                token=tokens[name],
            )
            backend_python(name, MEMBERSHIP_STATUS, {
                "QUAL_TENANT": target.tenant_id, "QUAL_SUBJECT": subject, "QUAL_STATUS": "active",
            })
            report["tenants"][name]["identity_denials"] = {**auth_denials, "membership": revoked_status}
            report["assertions"][f"T05_{name}_issuer_audience_expiry_membership"] = (
                all(status in {401, 403} for status in auth_denials.values())
                and revoked_status in {401, 403}
            )

        for name, target in runtime.TARGETS.items():
            logout_status, _ = runtime.request(target.base_url, "POST", "/api/auth/logout", {}, token=tokens[name])
            replay_status, _ = runtime.request(target.base_url, "GET", "/api/v1/findings?limit=1", token=tokens[name])
            report["assertions"][f"T05_{name}_revoked_session_replay_denied"] = (
                logout_status == 200 and replay_status in {401, 403}
            )

        # Cross-tenant canaries must not occur in the peer pod logs. This scans
        # every application container, not only the backend's access log.
        for name in ("a", "b"):
            other = "b" if name == "a" else "a"
            logs = runtime.kubectl(name, "logs", "-n", "vigil", "--all-containers", "--prefix", "--tail=-1", "-l", "app.kubernetes.io/instance=vigil", check=False)
            combined = logs.stdout + logs.stderr
            report["assertions"][f"T15_{name}_foreign_observability_canary_absent"] = canaries[other] not in combined

        report["result"] = "passed" if all(report["assertions"].values()) else "failed"
        return 0 if report["result"] == "passed" else 1
    except Exception as exc:
        report.update(result="failed", error=str(exc))
        return 1
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        path = EVIDENCE / "isolation-matrix.json"
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        if forwards:
            runtime.stop_forwards(forwards)
        print(json.dumps({"result": report.get("result"), "evidence": str(path), "assertions": report["assertions"]}, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
