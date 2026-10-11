import { createHash } from "node:crypto";
import type { RegisteredTool, ToolResult } from "../contracts/tool.js";
import type { ManagedExecutionIdentity } from "./managed.js";

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
  signature: string;
}

export interface ManagedGatewayClient {
  authorize(input: {
    grant?: ManagedGrant;
    identity: ManagedExecutionIdentity;
    tool: string;
    args: Record<string, unknown>;
  }, signal?: AbortSignal): Promise<ToolResult>;
}

function digest(args: Record<string, unknown>): string {
  const stable = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(stable);
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, held]) => [key, stable(held)]));
    }
    return value;
  };
  return createHash("sha256").update(JSON.stringify(stable(args))).digest("hex");
}

export function invocationId(executionId: string, tool: string, args: Record<string, unknown>): string {
  const hex = createHash("sha256").update(`${executionId}\n${tool}\n${digest(args)}`).digest("hex").slice(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Build the callback used by managed ToolDispatch. The gateway remains authoritative. */
export function managedAuthorizer(client: ManagedGatewayClient, grant: ManagedGrant | undefined, identity: ManagedExecutionIdentity) {
  return async (tool: RegisteredTool, args: Record<string, unknown>, signal?: AbortSignal): Promise<ToolResult> => {
    if (grant !== undefined) {
      if (grant.execution_id !== identity.execution_id) throw new Error("grant execution does not match the run");
      if (grant.tenant_id !== identity.tenant_id || grant.deployment_id !== identity.deployment_id) throw new Error("grant tenant does not match the run");
      if (grant.workload_key_id !== identity.worker_key_id) throw new Error("grant workload does not match the worker");
      if (Date.parse(grant.expires_at) <= Date.now()) throw new Error("tool grant expired");
      if (grant.argument_digest !== digest(args)) throw new Error("tool arguments are outside the grant");
    }
    return client.authorize({ grant, identity, tool: tool.id, args }, signal);
  };
}
