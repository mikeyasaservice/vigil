/** A domain-neutral evaluation seam. Managed workflows own the wire contract. */
export interface Reasoner {
  evaluate(
    input: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<Record<string, unknown>>;
}
