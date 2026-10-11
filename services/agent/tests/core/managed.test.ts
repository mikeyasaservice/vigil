import { describe, expect, it, afterEach } from "vitest";
import { verifyManagedJob, ManagedAdmissionError } from "../../core/managed.js";

afterEach(() => {
  delete process.env["VIGIL_EXECUTION_PROFILE"];
  delete process.env["VIGIL_MANAGED_AUTHORITY_PUBLIC_KEY"];
  delete process.env["VIGIL_DEPLOYMENT_ID"];
});

describe("managed queue admission", () => {
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
});
