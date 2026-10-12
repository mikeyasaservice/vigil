"""Run a budget-limited DSPy optimizer inside one tenant data plane.

The command reads a deployment-local dataset and emits declarative JSON state.
It does not upload examples, traces, prompts or demonstrations.  Production
promotion still requires separate held-out and safety evaluations plus a
distinct approver.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.agents.managed_execution import Ed25519Signer
from services.reasoner.lifecycle import (
    LifecycleError,
    candidate_payload,
    digest,
    digest_bytes,
    load_local_dataset,
    write_candidate,
)
from services.reasoner.programs.triage_v1 import PROGRAM_ID, build_program


def _credential(reference: str) -> str:
    key = "AUTOBOT_REASONER_CREDENTIAL_" + reference.upper().replace("-", "_")
    value = os.getenv(key, "")
    if not value:
        raise LifecycleError("model credential reference is unavailable")
    return value


def _signer(reference: str) -> Ed25519Signer:
    key = "AUTOBOT_REASONER_SIGNING_KEY_" + reference.upper().replace("-", "_")
    value = os.getenv(key, "")
    try:
        padded = value + "=" * (-len(value) % 4)
        return Ed25519Signer(
            Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(padded))
        )
    except (TypeError, ValueError) as exc:
        raise LifecycleError("candidate signing key reference is unavailable") from exc


def _examples(dspy: Any, rows: list[dict[str, Any]]) -> list[Any]:
    examples = []
    for row in rows:
        expected = row["expected"]
        examples.append(
            dspy.Example(
                finding_ids=row["input"]["finding_ids"],
                evidence=row["input"]["evidence"],
                hypotheses=["candidate must remain grounded in tenant-local evidence"],
                evidence_refs=expected["evidence_refs"],
                confidence=expected["min_confidence"],
                limitations=[],
                proposed_actions=expected["allowed_actions"],
            ).with_inputs("finding_ids", "evidence")
        )
    return examples


def _metric(example: Any, prediction: Any, trace: Any = None) -> float:
    del trace
    refs = (
        prediction.evidence_refs
        if isinstance(prediction.evidence_refs, list)
        else [str(prediction.evidence_refs)]
    )
    actions = (
        prediction.proposed_actions
        if isinstance(prediction.proposed_actions, list)
        else [str(prediction.proposed_actions)]
    )
    grounded = set(example.evidence_refs).issubset(set(refs))
    safe = set(actions).issubset(set(example.proposed_actions)) and all(
        str(item).startswith("propose:") for item in actions
    )
    try:
        confidence = 0 <= float(prediction.confidence) <= 1
    except (TypeError, ValueError):
        confidence = False
    return float(grounded and safe and confidence)


def _usage(lm: Any) -> tuple[int, int]:
    tokens = 0
    cost_microusd = 0
    for item in getattr(lm, "history", ()):
        usage = item.get("usage", {}) if isinstance(item, dict) else {}
        tokens += int(usage.get("total_tokens", 0) or 0)
        cost = item.get("cost", 0) if isinstance(item, dict) else 0
        cost_microusd += int(float(cost or 0) * 1_000_000)
    return tokens, cost_microusd


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--base-program-digest", required=True)
    parser.add_argument("--model-config-digest", required=True)
    parser.add_argument(
        "--optimizer", choices=("bootstrap-few-shot", "miprov2"), required=True
    )
    parser.add_argument("--optimizer-config", type=Path, required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--credential-ref", required=True)
    parser.add_argument("--signing-key-ref", required=True)
    parser.add_argument("--max-tokens", type=int, required=True)
    parser.add_argument("--max-cost-microusd", type=int, required=True)
    parser.add_argument("--seed", type=int, default=9)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.max_tokens <= 0 or args.max_cost_microusd <= 0:
        parser.error("optimization budgets must be positive")
    try:
        dataset = load_local_dataset(
            args.dataset, tenant_id=args.tenant_id, deployment_id=args.deployment_id
        )
        optimizer_config = json.loads(args.optimizer_config.read_text(encoding="utf-8"))
        if not isinstance(optimizer_config, dict):
            raise LifecycleError("optimizer config must be an object")
        import dspy  # type: ignore[import-not-found]

        lm = dspy.LM(args.provider, api_key=_credential(args.credential_ref))
        dspy.configure(lm=lm)
        trainset = _examples(dspy, dataset["splits"]["train"])
        if args.optimizer == "miprov2":
            optimizer = dspy.MIPROv2(
                metric=_metric,
                auto=str(optimizer_config.get("auto", "light")),
                seed=args.seed,
                num_threads=int(optimizer_config.get("num_threads", 1)),
            )
        else:
            optimizer = dspy.BootstrapFewShot(
                metric=_metric,
                max_bootstrapped_demos=int(
                    optimizer_config.get("max_bootstrapped_demos", 4)
                ),
                max_labeled_demos=int(optimizer_config.get("max_labeled_demos", 4)),
                max_rounds=int(optimizer_config.get("max_rounds", 1)),
            )
        compiled = optimizer.compile(build_program(), trainset=trainset)
        used_tokens, used_cost = _usage(lm)
        if used_tokens > args.max_tokens or used_cost > args.max_cost_microusd:
            raise LifecycleError("optimizer exceeded its token or cost budget")
        with tempfile.TemporaryDirectory(prefix="autobot-dspy-state-") as temporary:
            state_path = Path(temporary) / "state.json"
            compiled.save(str(state_path), save_program=False)
            state = json.loads(state_path.read_text(encoding="utf-8"))
        dependency_digest = digest_bytes(
            (Path(__file__).parent / "requirements.lock").read_bytes()
        )
        payload = candidate_payload(
            tenant_id=args.tenant_id,
            deployment_id=args.deployment_id,
            program_id=PROGRAM_ID,
            base_program_digest=args.base_program_digest,
            dataset_digest=digest(dataset),
            optimizer_name=args.optimizer,
            optimizer_config_digest=digest(optimizer_config),
            model_config_digest=args.model_config_digest,
            dependency_digest=dependency_digest,
            state=state,
        )
        candidate_digest = write_candidate(args.output, payload)
        signature = _signer(args.signing_key_ref).sign(payload)
        args.receipt.write_text(
            json.dumps(
                {
                    "schema_version": "autobot.dspy.optimization-receipt/v1",
                    "tenant_id": args.tenant_id,
                    "deployment_id": args.deployment_id,
                    "program_id": PROGRAM_ID,
                    "candidate_digest": candidate_digest,
                    "candidate_signature": signature,
                    "dataset_digest": digest(dataset),
                    "optimizer_config_digest": digest(optimizer_config),
                    "model_config_digest": args.model_config_digest,
                    "dependency_digest": dependency_digest,
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
    except (ImportError, OSError, ValueError, LifecycleError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
