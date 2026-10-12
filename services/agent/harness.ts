import OpenAI from "openai";
import type { RunKind } from "./contracts/events.js";
import type { RegisteredTool, ToolPrincipal, ToolResult } from "./contracts/tool.js";
import { budgetOf, FRESH, unmeteredQuota, type Seed } from "./core/budget.js";
import { noPrices } from "./core/prices.js";
import { httpPrices } from "./core/prices.js";
import { Limiter } from "./core/limiter.js";
import type { Harness } from "./core/loop.js";
import { nullMemory } from "./core/memory.js";
import { httpRecall, managedRecall } from "./core/recall.js";
import { registryOf } from "./core/registry.js";
import { remoteDispatch } from "./core/remote.js";
import { managedAuthorizer, type ManagedGatewayClient, type ManagedGrant } from "./core/managed-gateway.js";
import type { ManagedExecutionIdentity } from "./core/managed.js";
import { httpReasoner } from "./managed/reasoner.js";
import type { Memory, State } from "./core/seams.js";
import type { RunSpec } from "./core/spec.js";
import { httpVirtualKey } from "./core/vk.js";
import { openAiSurface } from "./core/wire.js";
import { toolsFrom } from "./tools/remote.js";
import { grantsOf as chatGrants } from "./workflows/chat/workflow.js";
import { grantsOf as composeGrants } from "./workflows/compose/workflow.js";
import { grantsOf as leadGrants } from "./workflows/lead/workflow.js";

// One name for the shared secret on both sides of the boundary — Python reads it
// as AGENT_INTERNAL_TOKEN. VIGIL_TOOLS_TOKEN is the older spelling, still read.
export function internalToken(): string {
  return process.env["AGENT_INTERNAL_TOKEN"] ?? process.env["VIGIL_TOOLS_TOKEN"] ?? "";
}

// One per process, not one per run. A client per run opens its own connection pool
// and reuses no keep-alive; a limiter per run means N runs get N times the rate.
// /v1 is Bifrost's OpenAI-format surface and BIFROST_URL names the gateway, not
// that surface: core/llm/router/router.py appends the same suffix to the same
// variable. Without it every call reaches the gateway root and answers 405.
//
// maxRetries: 0 because the limiter is the retry policy. The SDK's own default would
// multiply against the limiter's and the gateway's, billing every attempt.
const client = new OpenAI({
  baseURL: `${(process.env["BIFROST_URL"] ?? "http://bifrost:8080").replace(/\/+$/, "")}/v1`,
  apiKey: process.env["BIFROST_API_KEY"] ?? "unused",
  maxRetries: 0,
  timeout: Number(process.env["VIGIL_LLM_TIMEOUT_MS"] ?? 600_000),
});

const limiter = new Limiter({ rpm: 500, tpm: 400_000 }, 4);

// Memoised across runs, since a per-run memo dies with the run, but only for as long
// as the backend keeps its own copy: MODEL_CATALOG_REFRESH_INTERVAL_S is the variable
// core/config.py reads, and its default there.
const pricing = {
  url: process.env["VIGIL_PRICING_URL"] ?? "http://localhost:6987/internal/pricing",
  token: internalToken(),
  ttlMs: Number(process.env["MODEL_CATALOG_REFRESH_INTERVAL_S"] ?? 300) * 1000,
};
const prices = httpPrices(pricing);

// The Settings → Budgets key, sent on every model call so Bifrost's budget binds
// agent runs too. Read per process, never carried in a RunSpec.
const vk = httpVirtualKey(pricing);

// Which grants a run kind's roles hold. Compose grants per phase agent and chat
// per declared tool, because neither reads a roster the arch wrote.
function grantsFor(kind: RunKind, spec: RunSpec): Record<string, readonly string[]> {
  if (kind === "compose") return composeGrants(spec);
  if (kind === "chat") return chatGrants(spec);
  return leadGrants(spec);
}

// The six injected parts, assembled per run because the model, the grants and the
// budget are all the spec's. Nothing here is shared between two runs.
// The gateway's own namespacing: "<provider>/<model>". Left bare when the spec
// names no provider, which is every config written before this field existed.
function wireModel(spec: { model: string; provider?: string }): string {
  return spec.provider ? `${spec.provider}/${spec.model}` : spec.model;
}

export function harnessFor<K extends Record<string, unknown>>(
  kind: RunKind,
  spec: RunSpec,
  state: State<K>,
  memory: Memory = nullMemory,
  seed: Seed = FRESH,
  principal?: ToolPrincipal,
  managedIdentity?: ManagedExecutionIdentity,
): Harness<K> {
  const tools = process.env["VIGIL_TOOLS_URL"] ?? "http://localhost:6987/internal/tools/invoke";
  const managed = process.env["VIGIL_EXECUTION_PROFILE"] === "managed";
  let authorize: ((tool: RegisteredTool, args: Record<string, unknown>, signal?: AbortSignal) => Promise<ToolResult>) | undefined;
  if (managed && managedIdentity !== undefined) {
    try {
      const gateway = (process.env["VIGIL_MANAGED_GATEWAY_URL"] ?? "http://127.0.0.1:15001/v1").replace(/\/$/, "");
      const boundBody = (input: { identity: ManagedExecutionIdentity; tool: string; args: Record<string, unknown>; max_rows: number; timeout_ms: number }) => ({
        execution_id: input.identity.execution_id,
        tenant_id: input.identity.tenant_id,
        deployment_id: input.identity.deployment_id,
        worker_key_id: input.identity.worker_key_id,
        claim_token: input.identity.jti,
        attestation: input.identity.attestation,
        tool: input.tool,
        args: input.args,
        max_rows: input.max_rows,
        timeout_ms: input.timeout_ms,
      });
      const client: ManagedGatewayClient = {
        async issue(input, signal): Promise<ManagedGrant> {
          const response = await fetch(`${gateway}/grants`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(boundBody(input)),
            signal,
          });
          if (!response.ok) throw new Error(`managed grant denied (${response.status})`);
          const grant = await response.json() as ManagedGrant;
          if (typeof grant.signature !== "string" || grant.signature === "") throw new Error("managed gateway returned an unsigned grant");
          return grant;
        },
        async authorize(input, signal): Promise<ToolResult> {
          const response = await fetch(`${gateway}/authorize`, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-vigil-invocation-id": input.invocation_id,
            },
            body: JSON.stringify({ ...boundBody(input), grant: input.grant }),
            signal,
          });
          if (!response.ok) throw new Error(`managed gateway denied (${response.status})`);
          const result = await response.json() as ToolResult;
          if (typeof result !== "object" || result === null || !("ok" in result)) throw new Error("managed gateway returned an invalid tool result");
          return result;
        },
      };
      authorize = managedAuthorizer(client, managedIdentity);
    } catch {
      authorize = undefined;
    }
  }
  return {
    // Bare id for pricing, namespaced id on the wire — see openAiSurface. Without
    // the namespace the gateway matched "gemini-2.5-flash" to whichever provider
    // claimed it first, so a chat pointed at Vertex was answered (or refused) by
    // a different account entirely. The same provider is handed to pricing: the
    // gateway bills nothing of its own, and a catalog left to guess from the
    // model's name priced a paid "llama" on a commercial host at $0.
    provider: openAiSurface(client, spec.model, limiter, spec.provider ?? "bifrost", wireModel(spec), vk, spec.effort),
    registry: registryOf(toolsFrom(spec.tools), grantsFor(kind, spec)),
    dispatch: remoteDispatch({
      url: tools,
      token: internalToken(),
      ...(principal === undefined ? {} : { principal }),
      ...(managed ? { managed: true, ...(authorize === undefined ? {} : { authorize }) } : {}),
    }),
    ...(managed && managedIdentity !== undefined ? { reasoner: httpReasoner({ url: process.env["VIGIL_REASONER_URL"] ?? "http://127.0.0.1:15002/v1/evaluate", token: process.env["VIGIL_REASONER_INTERNAL_TOKEN"] ?? "", programDigest: managedIdentity.program_digest, identity: managedIdentity }) } : {}),
    budget: budgetOf(spec.budgets, unmeteredQuota, Date.now, seed, managed ? noPrices : prices),
    // Wrapped rather than replaced: whatever the caller passed still answers the
    // cue-shaped recall, and the keyed read is added over the same endpoint the
    // tools go to -- one address for the far side, not two to keep in step.
    memory: managed
      ? (authorize === undefined ? nullMemory : managedRecall(memory, authorize))
      : httpRecall(memory, { url: tools, token: internalToken() }),
    state,
  };
}

// Injected so a test drives a run without a provider behind it. The seam is the
// harness itself, which is the only part of a run that reaches outside the process.
export type HarnessFactory = <K extends Record<string, unknown>>(
  kind: RunKind,
  spec: RunSpec,
  state: State<K>,
  memory?: Memory,
  seed?: Seed,
  // Only chat has a person behind it; the worker and hunts pass none.
  principal?: ToolPrincipal,
  managedIdentity?: ManagedExecutionIdentity,
) => Harness<K>;
