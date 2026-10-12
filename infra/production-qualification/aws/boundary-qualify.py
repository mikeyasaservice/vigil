#!/usr/bin/env python3
"""Exercise live AWS identity, network, and managed-gateway boundaries for A/B."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(os.getenv("VIGIL_AWS_QUALIFICATION_ROOT", "/tmp/vigil-aws-qualification"))
AWS_CONFIG = ROOT / "aws-config"
RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
EVIDENCE = ROOT / "evidence" / RUN_ID
TENANTS = ("a", "b")


def tenant_env(name: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        AWS_CONFIG_FILE=str(AWS_CONFIG), AWS_PROFILE=f"vigil-tenant-{name}",
        AWS_REGION="us-east-1", AWS_DEFAULT_REGION="us-east-1",
        AWS_EC2_METADATA_DISABLED="true", KUBECONFIG=str(ROOT / f"tenant-{name}" / "kubeconfig"),
    )
    return env


def run(command: list[str], *, env: dict[str, str] | None = None, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, env=env, input=input_text, text=True, capture_output=True, check=False)


def require(result: subprocess.CompletedProcess[str], label: str) -> str:
    if result.returncode:
        lines = (result.stdout + "\n" + result.stderr).strip().splitlines()
        raise RuntimeError(f"{label} failed: {' | '.join(lines[-6:])}")
    return result.stdout.strip()


def kubectl(name: str, *args: str) -> subprocess.CompletedProcess[str]:
    return run(["kubectl", *args], env=tenant_env(name))


def outputs(name: str) -> dict[str, Any]:
    return json.loads((ROOT / f"tenant-{name}" / "outputs.json").read_text())


def aws(name: str, *args: str, credentials: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = tenant_env(name)
    if credentials is not None:
        env.pop("AWS_PROFILE", None)
        env.update(
            AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
            AWS_ACCESS_KEY_ID=credentials["AccessKeyId"],
            AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"],
            AWS_SESSION_TOKEN=credentials["SessionToken"],
        )
    return run(["aws", *args], env=env)


def assume_external_secrets(name: str, role_arn: str) -> dict[str, str]:
    token_result = kubectl(
        name, "create", "token", "external-secrets", "-n", "external-secrets",
        "--audience", "sts.amazonaws.com", "--duration", "15m",
    )
    token = require(token_result, f"tenant {name} projected service-account token")
    assumed = aws(
        name, "sts", "assume-role-with-web-identity", "--role-arn", role_arn,
        "--role-session-name", f"vigil-boundary-{name}-{RUN_ID.lower()}",
        "--web-identity-token", token, "--duration-seconds", "900", "--output", "json",
    )
    return json.loads(require(assumed, f"tenant {name} workload identity"))["Credentials"]


def denied(result: subprocess.CompletedProcess[str]) -> bool:
    message = (result.stdout + "\n" + result.stderr).lower()
    return result.returncode != 0 and any(value in message for value in ("accessdenied", "not authorized", "explicit deny"))


NETWORK_PROBE = r'''
import dns from "node:dns/promises";
import net from "node:net";

const targets = JSON.parse(process.env.QUAL_TARGETS);
async function probe(host, port) {
  let addresses;
  try { addresses = await dns.lookup(host, {all:true}); }
  catch (error) { return {dns:false, connected:false, error:error.code || error.name}; }
  const connected = await new Promise((resolve) => {
    const socket = net.createConnection({host, port});
    const timer = setTimeout(() => { socket.destroy(); resolve(false); }, 3500);
    socket.once("connect", () => { clearTimeout(timer); socket.destroy(); resolve(true); });
    socket.once("error", () => { clearTimeout(timer); resolve(false); });
  });
  return {dns:true, connected, addresses:addresses.map((value) => value.address)};
}
const result = {};
for (const [name, target] of Object.entries(targets)) result[name] = await probe(target.host, target.port);
console.log(JSON.stringify(result));
'''


BYPASS_PROBE = r'''
import dns from "node:dns/promises";
const timeout = (ms) => AbortSignal.timeout(ms);
const backend = "vigil-backend.vigil.svc.cluster.local";
const connector = "vigil-connector.vigil.svc.cluster.local";
const resolved = {backend:(await dns.lookup(backend)).address, connector:(await dns.lookup(connector)).address};
let backendReachable = false;
let backendStatus = null;
let backendError = "";
try {
  const response = await fetch(`http://${backend}:6987/health`, {signal:timeout(3500)});
  backendReachable = true;
  backendStatus = response.status;
} catch (error) { backendError = error.cause?.code || error.name; }
let connectorReachable = false;
let connectorError = "";
try {
  const response = await fetch(`http://${connector}:8083/healthz`, {signal:timeout(3500)});
  connectorReachable = true;
  connectorError = `http-${response.status}`;
} catch (error) { connectorError = error.cause?.code || error.name; }
console.log(JSON.stringify({resolved, backend_reachable:backendReachable, backend_status:backendStatus, backend_error:backendError, connector_reachable:connectorReachable, connector_error:connectorError}));
'''


LEGACY_ROUTE_PROBE = r'''
import json
import os
import urllib.error
import urllib.request

body = json.dumps({"tool":"get_finding","args":{"finding_id":"qualification-collision"},"bounds":{"max_rows":1,"timeout_ms":1000}}).encode()
request = urllib.request.Request(
    "http://127.0.0.1:6987/internal/tools/invoke", method="POST", data=body,
    headers={"Content-Type":"application/json", "Authorization":"Bearer " + os.environ["AGENT_INTERNAL_TOKEN"]},
)
try:
    with urllib.request.urlopen(request, timeout=5) as response:
        print(json.dumps({"status":response.status}))
except urllib.error.HTTPError as error:
    print(json.dumps({"status":error.code}))
'''


def worker_probe(name: str, script: str, extra_env: dict[str, str] | None = None) -> dict[str, Any]:
    command = ["exec", "-n", "vigil", "deploy/vigil-agent-worker", "-c", "agent-worker", "--"]
    if extra_env:
        command += ["env", *(f"{key}={value}" for key, value in extra_env.items())]
    command += ["node", "--input-type=module", "-e", script]
    result = kubectl(name, *command)
    return json.loads(require(result, f"tenant {name} worker boundary probe").splitlines()[-1])


def legacy_route_probe(name: str) -> dict[str, Any]:
    result = kubectl(
        name, "exec", "-i", "-n", "vigil", "deploy/vigil-backend", "-c", "backend", "--",
        "python", "-c", LEGACY_ROUTE_PROBE,
    )
    return json.loads(require(result, f"tenant {name} legacy route probe").splitlines()[-1])


def main() -> int:
    EVIDENCE.mkdir(parents=True, mode=0o700)
    tenant_outputs = {name: outputs(name) for name in TENANTS}
    report: dict[str, Any] = {
        "run_id": RUN_ID, "started_at": datetime.now(timezone.utc).isoformat(),
        "assertions": {}, "tenants": {},
    }
    try:
        for name in TENANTS:
            foreign = "b" if name == "a" else "a"
            own = tenant_outputs[name]
            other = tenant_outputs[foreign]
            credentials = assume_external_secrets(name, own["externalSecretsRoleArn"])
            own_secret = aws(
                name, "secretsmanager", "get-secret-value", "--secret-id", own["runtimeSecretArn"],
                "--query", "ARN", "--output", "text", credentials=credentials,
            )
            foreign_secret = aws(
                name, "secretsmanager", "get-secret-value", "--secret-id", other["runtimeSecretArn"],
                "--query", "ARN", "--output", "text", credentials=credentials,
            )
            workload_identity = {
                "own_secret_read": own_secret.returncode == 0,
                "foreign_secret_denied": denied(foreign_secret),
            }

            # A deploy role must not be able to read the other tenant's runtime credential.
            deployer_foreign = aws(
                name, "secretsmanager", "get-secret-value", "--secret-id", other["runtimeSecretArn"],
                "--query", "ARN", "--output", "text",
            )
            deployer_boundary = {"foreign_secret_denied": denied(deployer_foreign)}

            targets = {
                "own_database": {"host": own["databaseEndpoint"], "port": 5432},
                "own_cache": {"host": own["redisEndpoint"], "port": 6379},
                "foreign_database": {"host": other["databaseEndpoint"], "port": 5432},
                "foreign_cache": {"host": other["redisEndpoint"], "port": 6379},
            }
            network = worker_probe(name, NETWORK_PROBE, {"QUAL_TARGETS": json.dumps(targets, separators=(",", ":"))})
            bypass = worker_probe(name, BYPASS_PROBE)
            legacy_route = legacy_route_probe(name)
            network_ok = (
                network["own_database"]["dns"] and network["own_database"]["connected"]
                and network["own_cache"]["dns"] and network["own_cache"]["connected"]
                and network["foreign_database"]["dns"] and not network["foreign_database"]["connected"]
                and network["foreign_cache"]["dns"] and not network["foreign_cache"]["connected"]
            )
            bypass_ok = (
                not bypass["backend_reachable"] and not bypass["connector_reachable"]
                and legacy_route["status"] == 403
            )

            report["tenants"][name] = {
                "workload_identity": workload_identity,
                "deployer_boundary": deployer_boundary,
                "network": network,
                "gateway_bypass": bypass,
                "legacy_route": legacy_route,
                "resource_ids": {
                    "cluster": own["clusterName"], "database": own["databaseIdentifier"],
                    "cache": own["redisIdentifier"], "key_arn": own["keyArn"],
                },
            }
            report["assertions"][f"T02_T14_tenant_{name}_workload_secret_isolation"] = all(workload_identity.values())
            report["assertions"][f"T06_tenant_{name}_worker_bypass_denied"] = bypass_ok
            report["assertions"][f"T17_tenant_{name}_network_isolation"] = network_ok
            report["assertions"][f"T17_tenant_{name}_deployer_cannot_read_foreign_secret"] = deployer_boundary["foreign_secret_denied"]

        report["result"] = "passed" if all(report["assertions"].values()) else "failed"
        return 0 if report["result"] == "passed" else 1
    except Exception as exc:
        report["result"] = "failed"
        report["error"] = str(exc)
        return 1
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        path = EVIDENCE / "boundaries.json"
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"result": report.get("result"), "evidence": str(path), "assertions": report["assertions"]}, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
