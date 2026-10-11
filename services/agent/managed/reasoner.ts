import type { ProviderError } from "../core/provider.js";
import { ZERO_TOKENS } from "../contracts/budget.js";
import type { Provider, ProviderEvent, TurnRequest } from "../core/provider.js";
import type { Reasoner } from "../core/reasoner.js";
import type { ManagedExecutionIdentity } from "../core/managed.js";

export interface ReasonerInput extends Record<string, unknown> {
  execution_id: string;
  finding_ids: readonly string[];
  evidence: readonly Record<string, unknown>[];
  budget_tokens: number;
}

export interface ReasonerOutput extends Record<string, unknown> {
  hypotheses: readonly string[];
  evidence_refs: readonly string[];
  confidence: number;
  limitations: readonly string[];
  proposed_actions: readonly string[];
  input_tokens: number;
  output_tokens: number;
}

/** Adapt one pinned reasoner result to the ordinary harness Provider seam. */
export function reasonerProvider(result: ReasonerOutput): Provider {
  let reported = false;
  const rationale = [
    ...result.hypotheses,
    ...result.limitations.map((item) => `Limitation: ${item}`),
    ...(result.proposed_actions.length === 0
      ? []
      : [`Proposed follow-up (not executed): ${result.proposed_actions.join(", ")}`]),
  ].join(" ");
  return {
    model: "triage-dspy-v1",
    provider_type: "managed-reasoner",
    stream: async function* (request: TurnRequest): AsyncGenerator<ProviderEvent> {
      const content = request.emit === undefined
        ? rationale
        : JSON.stringify({ action: "CONCLUDE", rationale, citations: result.evidence_refs });
      yield { type: "text_delta", text: content };
      yield {
        type: "usage",
        tokens: reported
          ? ZERO_TOKENS
          : { input: result.input_tokens, output: result.output_tokens, cache_read: 0, cache_write: 0 },
      };
      reported = true;
    },
  };
}

export function validateReasonerResult(input: ReasonerInput, value: unknown): ReasonerOutput {
  if (typeof value !== "object" || value === null) throw new Error("reasoner returned no object");
  const held = value as Record<string, unknown>;
  const refs = Array.isArray(held.evidence_refs) ? held.evidence_refs.map(String) : [];
  const allowed = new Set(input.evidence.map((item) => String(item.evidence_id ?? "")));
  if (refs.some((ref) => !allowed.has(ref))) throw new Error("reasoner referenced evidence outside the input");
  const confidence = Number(held.confidence);
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) throw new Error("reasoner confidence is invalid");
  const actions = Array.isArray(held.proposed_actions) ? held.proposed_actions.map(String) : [];
  if (actions.some((action) => !action.startsWith("propose:"))) throw new Error("reasoner returned an executable action");
  return {
    hypotheses: Array.isArray(held.hypotheses) ? held.hypotheses.map(String) : [],
    evidence_refs: refs,
    confidence,
    limitations: Array.isArray(held.limitations) ? held.limitations.map(String) : [],
    proposed_actions: actions,
    input_tokens: Number(held.input_tokens ?? 0),
    output_tokens: Number(held.output_tokens ?? 0),
  };
}

export function httpReasoner(options: { url: string; token: string; programDigest: string; identity: ManagedExecutionIdentity; fetch?: typeof globalThis.fetch }): Reasoner {
  const call = options.fetch ?? globalThis.fetch;
  return {
    async evaluate(input, signal) {
      const response = await call(options.url, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${options.token}` },
        body: JSON.stringify({ program_id: options.identity.program_id, program_digest: options.programDigest, execution_identity: options.identity, input }),
        signal,
      });
      if (!response.ok) throw new Error(`reasoner answered ${response.status}`);
      try {
        return validateReasonerResult(input as ReasonerInput, await response.json());
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const wrapped = new Error(message) as ProviderError;
        wrapped.name = "ProviderError";
        throw wrapped;
      }
    },
  };
}
