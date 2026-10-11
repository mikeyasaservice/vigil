import type { ProviderError } from "./provider.js";

export interface ReasonerInput {
  execution_id: string;
  finding_ids: readonly string[];
  evidence: readonly Record<string, unknown>[];
  budget_tokens: number;
}

export interface ReasonerOutput {
  hypotheses: readonly string[];
  evidence_refs: readonly string[];
  confidence: number;
  limitations: readonly string[];
  proposed_actions: readonly string[];
  input_tokens: number;
  output_tokens: number;
}

export interface Reasoner {
  evaluate(input: ReasonerInput, signal?: AbortSignal): Promise<ReasonerOutput>;
}

function validate(input: ReasonerInput, value: unknown): ReasonerOutput {
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

export function httpReasoner(options: { url: string; token: string; programDigest: string; fetch?: typeof globalThis.fetch }): Reasoner {
  const call = options.fetch ?? globalThis.fetch;
  return {
    async evaluate(input, signal) {
      const response = await call(options.url, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${options.token}` },
        body: JSON.stringify({ program_id: "triage-dspy-v1", program_digest: options.programDigest, input }),
        signal,
      });
      if (!response.ok) throw new Error(`reasoner answered ${response.status}`);
      try {
        return validate(input, await response.json());
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const wrapped = new Error(message) as ProviderError;
        wrapped.name = "ProviderError";
        throw wrapped;
      }
    },
  };
}
