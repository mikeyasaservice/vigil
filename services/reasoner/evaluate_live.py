"""Budget-limited live evaluation for the pinned triage program.

This command is intentionally separate from CI. It requires an explicit model,
credential reference, and spend cap; the credential value is read from the
process environment and never printed or written to the result.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from services.reasoner.contracts import TriageInput
from services.reasoner.programs import triage_v1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", required=True, help="Explicit DSPy model/provider identifier")
    parser.add_argument("--credential-ref", required=True, help="Environment-backed credential reference")
    parser.add_argument("--spend-cap-usd", required=True, type=float)
    parser.add_argument("--price-per-1k-tokens", required=True, type=float)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.spend_cap_usd <= 0 or args.price_per_1k_tokens <= 0:
        parser.error("spend cap and token price must be positive")
    credential = os.getenv(f"VIGIL_REASONER_CREDENTIAL_{args.credential_ref.upper().replace('-', '_')}")
    if not credential:
        parser.error("credential reference is not available in the environment")

    try:
        import dspy
    except ImportError as exc:
        parser.error(f"DSPy is required for live evaluation: {exc}")
    dspy.configure(lm=dspy.LM(args.provider, api_key=credential))
    os.environ["VIGIL_REASONER_MODE"] = "live"

    rows = json.loads(args.dataset.read_text())
    if not isinstance(rows, list):
        parser.error("dataset must be a JSON array")
    started = time.monotonic()
    spent = 0.0
    results: list[dict[str, object]] = []
    for row in rows:
        value = TriageInput(
            execution_id=str(row["execution_id"]),
            finding_ids=tuple(str(item) for item in row["finding_ids"]),
            evidence=tuple(row["evidence"]),
            budget_tokens=int(row.get("budget_tokens", 0)),
        )
        output = triage_v1.evaluate(value)
        spent += (output.input_tokens + output.output_tokens) / 1000 * args.price_per_1k_tokens
        if spent > args.spend_cap_usd:
            parser.error("live evaluation spend cap exceeded")
        results.append({
            "execution_id": value.execution_id,
            "confidence": output.confidence,
            "grounded_evidence_refs": list(output.evidence_refs),
            "input_tokens": output.input_tokens,
            "output_tokens": output.output_tokens,
        })
    args.output.write_text(json.dumps({
        "provider": args.provider,
        "credential_ref": args.credential_ref,
        "spend_cap_usd": args.spend_cap_usd,
        "estimated_spend_usd": spent,
        "elapsed_seconds": time.monotonic() - started,
        "results": results,
    }, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
