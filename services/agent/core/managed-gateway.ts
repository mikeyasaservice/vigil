import { createHash } from "node:crypto";
import type { RegisteredTool, ToolResult } from "../contracts/tool.js";
import type { ManagedExecutionIdentity } from "./managed.js";
import type { InvocationContext } from "./seams.js";

export interface ManagedGrant {
  grant_id: string;
  execution_id: string;
  tenant_id: string;
  deployment_id: string;
  action: string;
  resource: string;
  argument_digest: string;
  approval_digest?: string | null;
  policy_version: string;
  revocation_epoch: number;
  issued_at: string;
  expires_at: string;
  workload_key_id: string;
  claim_jti: string;
  max_rows: number;
  timeout_ms: number;
  signature: string;
}

export interface ManagedGatewayClient {
  issue(input: {
    identity: ManagedExecutionIdentity;
    tool: string;
    args: Record<string, unknown>;
    max_rows: number;
    timeout_ms: number;
  }, signal?: AbortSignal): Promise<ManagedGrant>;
  authorize(input: {
    grant: ManagedGrant;
    identity: ManagedExecutionIdentity;
    tool: string;
    args: Record<string, unknown>;
    invocation_id: string;
    max_rows: number;
    timeout_ms: number;
  }, signal?: AbortSignal): Promise<ToolResult>;
}

export function invocationId(executionId: string, logicalId: string): string {
  const hex = createHash("sha256").update(`${executionId}\n${logicalId}`).digest("hex").slice(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Build the callback used by managed ToolDispatch. The gateway remains authoritative. */
export function managedAuthorizer(client: ManagedGatewayClient, identity: ManagedExecutionIdentity) {
  return async (tool: RegisteredTool, args: Record<string, unknown>, signal?: AbortSignal, context?: InvocationContext): Promise<ToolResult> => {
    if (context === undefined || context.logicalId === "") throw new Error("managed dispatch requires a logical invocation id");
    const max_rows = tool.bounds.maxRows;
    const timeout_ms = tool.bounds.timeoutMs;
    const grant = await client.issue({ identity, tool: tool.id, args, max_rows, timeout_ms }, signal);
    if (grant.execution_id !== identity.execution_id) throw new Error("grant execution does not match the run");
    if (grant.tenant_id !== identity.tenant_id || grant.deployment_id !== identity.deployment_id) throw new Error("grant tenant does not match the run");
    if (grant.workload_key_id !== identity.worker_key_id || grant.claim_jti !== identity.jti) throw new Error("grant workload does not match the worker claim");
    if (Date.parse(grant.expires_at) <= Date.now()) throw new Error("tool grant expired");
    if (grant.max_rows !== max_rows || grant.timeout_ms !== timeout_ms) throw new Error("tool bounds are outside the grant");
    return client.authorize({ grant, identity, tool: tool.id, args, invocation_id: invocationId(identity.execution_id, context.logicalId), max_rows, timeout_ms }, signal);
  };
}
