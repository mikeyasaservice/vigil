import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import canonicalize from "canonicalize";
import { describe, expect, it, afterEach, vi } from "vitest";
import { claimManagedExecutionFromService, managedDigest, verifyManagedJob, ManagedAdmissionError } from "../../core/managed.js";
import { parseConfig } from "../../core/spec.js";
import { managedWorkflow, managedWorkflowDigest } from "../../managed/workflows.js";
import type { RunJob } from "../../contracts/job.js";

function admitted(prompt = "café"): RunJob {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  process.env["VIGIL_MANAGED_AUTHORITY_PUBLIC_KEY"] = raw.toString("base64url");
  process.env["VIGIL_DEPLOYMENT_ID"] = "deployment-a";
  const request = { arch: "", playbook: "workflow:triage-v1", config: "", prompt, finding_ids: ["finding-a"] };
  const requestDigest = createHash("sha256").update(canonicalize(request)!).digest("hex");
  const findingReferenceDigest = createHash("sha256").update(canonicalize({ finding_ids: request.finding_ids })!).digest("hex");
  const admission = {
    schema_version: 3,
    admission_id: "admission-a",
    context: { tenant_id: "tenant-a", deployment_id: "deployment-a", subject_id: "user-a", issuer: "issuer", roles: ["analyst"], membership_version: 1, policy_version: "policy-1", request_id: "request-a" },
    workflow_id: "triage-v1", workflow_digest: "workflow-digest",
    program_id: "triage-dspy-v1", program_digest: "program-digest",
    request_digest: requestDigest, issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 60_000).toISOString(), revocation_epoch: 0,
  };
  const unsigned = {
    schema_version: 3 as const, admission, execution_id: "execution-a-123456789",
    reason: "start" as const,
    references: { run_id: "run-a", run_kind: "investigate", request_digest: requestDigest, workflow_id: "triage-v1", workflow_digest: "workflow-digest", program_id: "triage-dspy-v1", program_digest: "program-digest", finding_reference_digest: findingReferenceDigest },
  };
  return {
    schema_version: 1, run_id: "run-a", run_kind: "investigate", tenant_id: "tenant-a",
    enqueued_at: new Date().toISOString(), enqueued_by: "user-a", reason: "start", request,
    managed: { ...unsigned, signature: sign(null, Buffer.from(canonicalize(unsigned)!), privateKey).toString("base64url") },
  };
}

afterEach(() => {
  delete process.env["VIGIL_EXECUTION_PROFILE"];
  delete process.env["VIGIL_MANAGED_AUTHORITY_PUBLIC_KEY"];
  delete process.env["VIGIL_DEPLOYMENT_ID"];
  delete process.env["VIGIL_WORKER_SPIFFE_ID"];
  delete process.env["VIGIL_MANAGED_CAPABILITIES"];
  vi.unstubAllGlobals();
});

describe("managed queue admission", () => {
  it("resolves only the shipped workflow at its admitted digest", async () => {
    const digest = managedWorkflowDigest();
    const layers = await managedWorkflow("workflow:triage-v1", digest);
    expect(layers.playbook).toContain("name: Managed finding triage");
    expect(layers.config).toContain("id: get_finding");
    expect(parseConfig(layers.config).runtime.recall_limit).toBe(1);
    await expect(managedWorkflow("workflow:triage-v1", `${digest}-altered`)).rejects.toThrow(/artifact/);
    await expect(managedWorkflow("workflow:foreign", digest)).rejects.toThrow(/does not approve/);
  });

  it("rejects a job without a signed envelope in managed mode", () => {
    process.env["VIGIL_EXECUTION_PROFILE"] = "managed";
    const job = {
      schema_version: 1,
      run_id: "run-a",
      run_kind: "investigate" as const,
      tenant_id: "tenant-a",
      enqueued_at: new Date().toISOString(),
      enqueued_by: "user-a",
      reason: "resume" as const,
    };
    expect(() => verifyManagedJob(job)).toThrow(ManagedAdmissionError);
  });

  it("rejects a malformed work binding before execution", () => {
    process.env["VIGIL_EXECUTION_PROFILE"] = "managed";
    process.env["VIGIL_MANAGED_AUTHORITY_PUBLIC_KEY"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    process.env["VIGIL_DEPLOYMENT_ID"] = "deployment-a";
    const job = {
      schema_version: 1,
      run_id: "run-a",
      run_kind: "investigate" as const,
      tenant_id: "tenant-a",
      enqueued_at: new Date().toISOString(),
      enqueued_by: "user-a",
      reason: "resume" as const,
      managed: {
        schema_version: 2 as const,
        admission: { context: { deployment_id: "deployment-a" }, expires_at: new Date(Date.now() + 60_000).toISOString(), request_digest: "digest" },
        execution_id: "execution-a-123456789",
        reason: "resume" as const,
        references: { run_id: "run-b", run_kind: "investigate", request_digest: "digest" },
        signature: "invalid-signature",
      },
    };
    expect(() => verifyManagedJob(job)).toThrow(ManagedAdmissionError);
  });

  it("verifies non-ASCII requests with the shared JCS encoding", () => {
    process.env["VIGIL_EXECUTION_PROFILE"] = "managed";
    expect(() => verifyManagedJob(admitted("café 🔐"))).not.toThrow();
  });

  it("matches the cross-language RFC 8785 fixture", () => {
    const fixture = JSON.parse(readFileSync(
      new URL("../../../../contracts/fixtures/managed-canonicalization.json", import.meta.url),
      "utf8",
    )) as { input: unknown; canonical: string; sha256: string };
    expect(canonicalize(fixture.input)).toBe(fixture.canonical);
    expect(managedDigest(fixture.input)).toBe(fixture.sha256);
  });

  it("does not let a signed start envelope authorize a resume", () => {
    process.env["VIGIL_EXECUTION_PROFILE"] = "managed";
    const job = admitted() as Extract<RunJob, { reason: "start" }>;
    const { request: _request, ...base } = job;
    expect(() => verifyManagedJob({ ...base, reason: "resume" })).toThrow(/reason/);
  });

  it("requests no invented fallback capability from the security service", async () => {
    const job = admitted();
    const workloadId = "spiffe://autobot.local/ns/tenant-a/sa/worker";
    process.env["VIGIL_WORKER_SPIFFE_ID"] = workloadId;
    let requested: unknown;
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init?: RequestInit) => {
      requested = JSON.parse(String(init?.body));
      return new Response(JSON.stringify({
        execution_id: job.managed!.execution_id,
        tenant_id: "tenant-a", deployment_id: "deployment-a",
        workflow_id: "triage-v1", workflow_digest: "workflow-digest",
        program_id: "triage-dspy-v1", program_digest: "program-digest",
        workload_spiffe_id: workloadId, worker_key_id: workloadId,
        capabilities: ["get_finding"], policy_version: "policy-1",
        revocation_epoch: 0, issued_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 60_000).toISOString(),
        jti: "claim-1", attestation: "signed",
      }), { status: 200, headers: { "content-type": "application/json" } });
    }));

    await claimManagedExecutionFromService(job);

    expect(requested).toMatchObject({ capabilities: [] });
  });

  it("surfaces a stable security-service claim denial code", async () => {
    process.env["VIGIL_WORKER_SPIFFE_ID"] = "spiffe://autobot.local/ns/tenant-a/sa/worker";
    vi.stubGlobal("fetch", vi.fn(async () => new Response(
      JSON.stringify({ detail: { code: "claim_state_denied" } }),
      { status: 403, headers: { "content-type": "application/json" } },
    )));

    await expect(claimManagedExecutionFromService(admitted())).rejects.toThrow(
      /403, claim_state_denied/,
    );
  });
});
