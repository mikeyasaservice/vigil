"""Evaluate one signed DSPy candidate inside its tenant data plane.

Detailed failures and traces are written only to the local result file.  The
separate aggregate receipt has a fixed export-safe shape for the outbound BYOC
connector and contains no examples, prompts, evidence, or trace references.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import tempfile
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from core.agents.managed_execution import (
    Ed25519Signer,
    Ed25519Verifier,
    ManagedSecurityError,
)
from services.reasoner.contracts import TriageInput, TriageOutput
from services.reasoner.lifecycle import (
    EvaluationThresholds,
    LifecycleError,
    aggregate_receipt,
    canonical_json,
    digest,
    digest_bytes,
    evaluate_split,
    load_local_dataset,
    metric_contract_digest,
)
from services.reasoner.programs.triage_v1 import PROGRAM_ID, build_program


def _environment_value(prefix: str, reference: str) -> str:
    key = prefix + reference.upper().replace("-", "_")
    value = os.getenv(key, "")
    if not value:
        raise LifecycleError(f"credential reference {reference!r} is unavailable")
    return value


def _decode_key(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise LifecycleError("reasoner key reference is invalid") from exc


def _load_candidate(
    path: Path,
    *,
    tenant_id: str,
    deployment_id: str,
    expected_digest: str,
    signature: str,
    public_key: Ed25519PublicKey,
) -> Mapping[str, Any]:
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or resolved.is_symlink() or resolved.suffix != ".json":
        raise LifecycleError("candidate must be a regular declarative JSON file")
    raw = resolved.read_bytes()
    if digest_bytes(raw) != expected_digest:
        raise LifecycleError("candidate artifact digest does not match its pin")
    try:
        payload = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LifecycleError("candidate artifact could not be decoded") from exc
    if not isinstance(payload, Mapping) or canonical_json(payload) != raw:
        raise LifecycleError("candidate artifact is not canonical JSON")
    if (
        payload.get("schema_version") != "autobot.dspy.candidate/v1"
        or payload.get("tenant_id") != tenant_id
        or payload.get("deployment_id") != deployment_id
        or payload.get("program_id") != PROGRAM_ID
        or not isinstance(payload.get("state"), Mapping)
    ):
        raise LifecycleError("candidate artifact is outside the deployment binding")
    try:
        Ed25519Verifier(public_key, "reasoner-candidate").verify(payload, signature)
    except ManagedSecurityError as exc:
        raise LifecycleError("candidate artifact signature is invalid") from exc
    return payload


def _usage(lm: Any) -> tuple[int, int]:
    tokens = cost_microusd = 0
    for item in getattr(lm, "history", ()):
        usage = item.get("usage", {}) if isinstance(item, dict) else {}
        tokens += int(usage.get("total_tokens", 0) or 0)
        cost = item.get("cost", 0) if isinstance(item, dict) else 0
        cost_microusd += int(float(cost or 0) * 1_000_000)
    return tokens, cost_microusd


def _as_items(value: Any) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    return (str(value),)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evaluation-id", type=uuid.UUID, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--candidate-digest", required=True)
    parser.add_argument("--candidate-signature", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--model-config-digest", required=True)
    parser.add_argument(
        "--split", choices=("development", "holdout", "safety"), required=True
    )
    parser.add_argument("--thresholds", type=Path, required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--credential-ref", required=True)
    parser.add_argument("--verification-key-ref", required=True)
    parser.add_argument("--signing-key-ref", required=True)
    parser.add_argument("--max-tokens", type=int, required=True)
    parser.add_argument("--max-cost-microusd", type=int, required=True)
    parser.add_argument("--local-result", type=Path, required=True)
    parser.add_argument("--aggregate-receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.max_tokens <= 0 or args.max_cost_microusd <= 0:
        parser.error("evaluation budgets must be positive")
    try:
        dataset = load_local_dataset(
            args.dataset, tenant_id=args.tenant_id, deployment_id=args.deployment_id
        )
        thresholds_raw = json.loads(args.thresholds.read_text(encoding="utf-8"))
        thresholds = EvaluationThresholds(**thresholds_raw)
        public_key = Ed25519PublicKey.from_public_bytes(
            _decode_key(
                _environment_value(
                    "AUTOBOT_REASONER_VERIFY_KEY_", args.verification_key_ref
                )
            )
        )
        candidate = _load_candidate(
            args.candidate,
            tenant_id=args.tenant_id,
            deployment_id=args.deployment_id,
            expected_digest=args.candidate_digest,
            signature=args.candidate_signature,
            public_key=public_key,
        )
        import dspy  # type: ignore[import-not-found]

        per_call_limit = min(
            args.max_tokens,
            max(
                int(row["input"]["budget_tokens"])
                for row in dataset["splits"][args.split]
            ),
        )
        lm = dspy.LM(
            args.provider,
            api_key=_environment_value(
                "AUTOBOT_REASONER_CREDENTIAL_", args.credential_ref
            ),
            max_tokens=per_call_limit,
        )
        dspy.configure(lm=lm)
        program = build_program()
        with tempfile.TemporaryDirectory(prefix="autobot-dspy-candidate-") as temporary:
            state_path = Path(temporary) / "state.json"
            state_path.write_bytes(canonical_json(candidate["state"]))
            program.load(str(state_path))

        prior_tokens = prior_cost = 0
        exhausted = False

        def evaluate(value: TriageInput) -> TriageOutput:
            nonlocal exhausted, prior_tokens, prior_cost
            if exhausted:
                raise LifecycleError("evaluation budget is exhausted")
            prediction = program(
                finding_ids=list(value.finding_ids), evidence=list(value.evidence)
            )
            total_tokens, total_cost = _usage(lm)
            if total_tokens > args.max_tokens or total_cost > args.max_cost_microusd:
                exhausted = True
                raise LifecycleError("evaluation exceeded its token or cost budget")
            output = TriageOutput(
                hypotheses=_as_items(prediction.hypotheses),
                evidence_refs=_as_items(prediction.evidence_refs),
                confidence=float(prediction.confidence),
                limitations=_as_items(prediction.limitations),
                proposed_actions=_as_items(prediction.proposed_actions),
                input_tokens=max(0, total_tokens - prior_tokens),
            )
            prior_tokens, prior_cost = total_tokens, total_cost
            return output

        result = evaluate_split(dataset, args.split, evaluate, thresholds)
        used_tokens, used_cost = _usage(lm)
        if used_tokens > args.max_tokens or used_cost > args.max_cost_microusd:
            raise LifecycleError("evaluation exceeded its token or cost budget")
        result = replace(result, used_tokens=used_tokens)
        args.local_result.parent.mkdir(parents=True, exist_ok=True)
        args.local_result.write_text(
            json.dumps(
                {
                    "schema_version": "autobot.dspy.local-evaluation/v1",
                    "evaluation_id": str(args.evaluation_id),
                    "tenant_id": args.tenant_id,
                    "deployment_id": args.deployment_id,
                    "program_digest": args.candidate_digest,
                    "split_name": args.split,
                    "metrics": dict(result.metrics),
                    "failures": list(result.failures),
                    "passed": result.passed,
                    "used_tokens": used_tokens,
                    "used_cost_microusd": used_cost,
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        signing_key = Ed25519PrivateKey.from_private_bytes(
            _decode_key(
                _environment_value(
                    "AUTOBOT_REASONER_SIGNING_KEY_", args.signing_key_ref
                )
            )
        )
        receipt = aggregate_receipt(
            tenant_id=args.tenant_id,
            deployment_id=args.deployment_id,
            evaluation_id=str(args.evaluation_id),
            dataset_digest=digest(dataset),
            program_digest=args.candidate_digest,
            model_config_digest=args.model_config_digest,
            metric_contract_digest=metric_contract_digest(),
            split_name=args.split,
            result=result,
            sign=Ed25519Signer(signing_key).sign,
        )
        args.aggregate_receipt.parent.mkdir(parents=True, exist_ok=True)
        args.aggregate_receipt.write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (
        ImportError,
        OSError,
        TypeError,
        ValueError,
        LifecycleError,
    ) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
