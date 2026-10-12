import { describe, expect, it } from "vitest";
import { defineTool } from "../../contracts/tool.js";
import { invocationId, managedAuthorizer, type ManagedGatewayClient, type ManagedGrant } from "../../core/managed-gateway.js";
import type { ManagedExecutionIdentity } from "../../core/managed.js";

describe("managed invocation identity", () => {
  it("reuses an id for a retry of one logical call", () => {
    expect(invocationId("execution-a", "turn-1:call-7"))
      .toBe(invocationId("execution-a", "turn-1:call-7"));
  });

  it("does not collapse distinct calls with the same tool arguments", () => {
    expect(invocationId("execution-a", "turn-1:call-7"))
      .not.toBe(invocationId("execution-a", "turn-4:call-2"));
  });

  it("obtains an exact signed grant before every dispatch", async () => {
    const identity: ManagedExecutionIdentity = {
      execution_id: "execution-a", tenant_id: "tenant-a", deployment_id: "deployment-a",
      deployment_incarnation: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      workflow_id: "triage-v1", workflow_digest: "workflow-digest",
      program_id: "triage-dspy-v1", program_digest: "program-digest",
      workload_spiffe_id: "spiffe://autobot.local/ns/tenant-a/sa/worker",
      worker_key_id: "spiffe://autobot.local/ns/tenant-a/sa/worker",
      capabilities: ["get_finding"], policy_version: "policy-1", revocation_epoch: 0,
      issued_at: new Date().toISOString(), expires_at: new Date(Date.now() + 60_000).toISOString(),
      jti: "claim-1", attestation: "execution-attestation",
    };
    const calls: string[] = [];
    const client: ManagedGatewayClient = {
      async issue(input) {
        calls.push(`issue:${input.tool}:${input.max_rows}:${input.timeout_ms}`);
        return {
          grant_id: "grant-1", execution_id: identity.execution_id,
          tenant_id: identity.tenant_id, deployment_id: identity.deployment_id,
          deployment_incarnation: identity.deployment_incarnation,
          workflow_id: identity.workflow_id, workflow_digest: identity.workflow_digest,
          program_id: identity.program_id, program_digest: identity.program_digest,
          action: input.tool, resource: "finding-a", argument_digest: "signed-by-gateway",
          policy_version: identity.policy_version, revocation_epoch: identity.revocation_epoch,
          issued_at: new Date().toISOString(), expires_at: new Date(Date.now() + 60_000).toISOString(),
          workload_key_id: identity.worker_key_id, claim_jti: identity.jti,
          max_rows: input.max_rows, timeout_ms: input.timeout_ms, signature: "signed-grant",
        };
      },
      async authorize(input) {
        calls.push(`authorize:${input.grant.grant_id}:${input.invocation_id}`);
        return { ok: true, rows: [], rowCount: 0, capped: false, sourceSystem: "synthetic" };
      },
    };
    const tool = defineTool({
      id: "get_finding", description: "read", parameters: {},
      async execute() { throw new Error("the managed gateway owns dispatch"); },
    }, { maxRows: 7, timeoutMs: 900 });

    const result = await managedAuthorizer(client, identity)(
      tool, { finding_id: "finding-a" }, undefined, { logicalId: "turn-1:call-1" },
    );

    expect(result.ok).toBe(true);
    expect(calls[0]).toBe("issue:get_finding:7:900");
    expect(calls[1]).toMatch(/^authorize:grant-1:/);
  });

  it.each([
    ["execution", { execution_id: "execution-b" }],
    ["tenant", { tenant_id: "tenant-b" }],
    ["deployment", { deployment_id: "deployment-b" }],
    ["incarnation", { deployment_incarnation: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" }],
    ["workflow", { workflow_id: "workflow-b" }],
    ["workflow digest", { workflow_digest: "workflow-b-digest" }],
    ["program", { program_id: "program-b" }],
    ["program digest", { program_digest: "program-b-digest" }],
    ["workload", { workload_key_id: "spiffe://autobot.local/ns/tenant-b/sa/worker" }],
    ["claim", { claim_jti: "claim-b" }],
    ["policy", { policy_version: "policy-2" }],
    ["epoch", { revocation_epoch: 1 }],
    ["action", { action: "foreign_action" }],
    ["row bound", { max_rows: 8 }],
    ["time bound", { timeout_ms: 901 }],
  ])("refuses a substituted %s grant before dispatch", async (_label, mutation) => {
    const identity: ManagedExecutionIdentity = {
      execution_id: "execution-a", tenant_id: "tenant-a", deployment_id: "deployment-a",
      deployment_incarnation: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      workflow_id: "triage-v1", workflow_digest: "workflow-digest",
      program_id: "triage-dspy-v1", program_digest: "program-digest",
      workload_spiffe_id: "spiffe://autobot.local/ns/tenant-a/sa/worker",
      worker_key_id: "spiffe://autobot.local/ns/tenant-a/sa/worker",
      capabilities: ["get_finding"], policy_version: "policy-1", revocation_epoch: 0,
      issued_at: new Date().toISOString(), expires_at: new Date(Date.now() + 60_000).toISOString(),
      jti: "claim-a", attestation: "attestation-a",
    };
    let dispatches = 0;
    const base: ManagedGrant = {
      grant_id: "grant-a", execution_id: identity.execution_id, tenant_id: identity.tenant_id,
      deployment_id: identity.deployment_id, deployment_incarnation: identity.deployment_incarnation,
      workflow_id: identity.workflow_id, workflow_digest: identity.workflow_digest,
      program_id: identity.program_id, program_digest: identity.program_digest,
      action: "get_finding", resource: "finding-a", argument_digest: "digest-a",
      policy_version: identity.policy_version, revocation_epoch: identity.revocation_epoch,
      issued_at: new Date().toISOString(), expires_at: new Date(Date.now() + 60_000).toISOString(),
      workload_key_id: identity.worker_key_id, claim_jti: identity.jti,
      max_rows: 7, timeout_ms: 900, signature: "authority-signature",
    };
    const client: ManagedGatewayClient = {
      async issue() { return { ...base, ...mutation }; },
      async authorize() {
        dispatches += 1;
        return { ok: true, rows: [], rowCount: 0, capped: false, sourceSystem: "synthetic" };
      },
    };
    const tool = defineTool({
      id: "get_finding", description: "read", parameters: {},
      async execute() { throw new Error("gateway owns dispatch"); },
    }, { maxRows: 7, timeoutMs: 900 });

    await expect(managedAuthorizer(client, identity)(
      tool, { finding_id: "finding-a" }, undefined, { logicalId: "turn-1:call-1" },
    )).rejects.toThrow();
    expect(dispatches).toBe(0);
  });
});
