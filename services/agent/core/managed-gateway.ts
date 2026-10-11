import { createHash } from "node:crypto";
import type { RegisteredTool } from "../contracts/tool.js";

export interface ManagedGrant {
  execution_id: string;
  tenant_id: string;
  deployment_id: string;
  action: string;
  resource: string;
  argument_digest: string;
  expires_at: string;
  workload_key_id: string;
  signature: string;
}

export interface ManagedGatewayClient {
  authorize(input: {
    grant: ManagedGrant;
    tool: string;
    args: Record<string, unknown>;
  }, signal?: AbortSignal): Promise<void>;
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

/** Build the callback used by managed ToolDispatch. The gateway remains authoritative. */
export function managedAuthorizer(client: ManagedGatewayClient, grant: ManagedGrant, executionId: string) {
  return async (tool: RegisteredTool, args: Record<string, unknown>, signal?: AbortSignal): Promise<void> => {
    if (grant.execution_id !== executionId) throw new Error("grant execution does not match the run");
    if (Date.parse(grant.expires_at) <= Date.now()) throw new Error("tool grant expired");
    if (grant.argument_digest !== digest(args)) throw new Error("tool arguments are outside the grant");
    await client.authorize({ grant, tool: tool.id, args }, signal);
  };
}
