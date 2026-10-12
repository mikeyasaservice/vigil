#!/usr/bin/env python3
"""Inject a failed tenant A Helm rollout and prove atomic recovery plus tenant B continuity."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(os.getenv("VIGIL_AWS_QUALIFICATION_ROOT", "/tmp/vigil-aws-qualification"))
RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
EVIDENCE = ROOT / "evidence" / RUN_ID
REPO = Path(__file__).resolve().parents[3]


def load_runtime() -> ModuleType:
    path = Path(__file__).with_name("runtime-qualify.py")
    spec = importlib.util.spec_from_file_location("autobot_runtime_rollback", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("runtime qualification helpers are unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runtime = load_runtime()


def tenant_command(name: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, env=runtime.aws_env(name), text=True, capture_output=True, check=False)
    if check and result.returncode != 0:
        detail = (result.stdout + "\n" + result.stderr).strip().splitlines()
        raise RuntimeError(f"tenant {name} command failed: {' | '.join(detail[-6:])}")
    return result


def helm_history() -> list[dict[str, Any]]:
    result = tenant_command("a", "helm", "history", "vigil", "-n", "vigil", "-o", "json")
    return json.loads(result.stdout)


def worker_image(name: str) -> str:
    result = runtime.kubectl(
        name, "get", "deployment/vigil-agent-worker", "-n", "vigil",
        "-o", "jsonpath={.spec.template.spec.containers[?(@.name=='agent-worker')].image}",
    )
    return result.stdout.strip()


def main() -> int:
    EVIDENCE.mkdir(parents=True, mode=0o700)
    report: dict[str, Any] = {
        "run_id": RUN_ID,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "assertions": {},
    }
    forwards: list[Any] = []
    try:
        before_history = helm_history()
        before_image = worker_image("a")
        if "qual-20261011-r5" not in before_image:
            raise RuntimeError(f"tenant A is not on the qualified r5 worker: {before_image}")

        missing_tag = f"autobot-missing-{RUN_ID.lower()}"
        injected = tenant_command(
            "a", "helm", "upgrade", "vigil", str(REPO / "infra/helm/vigil"),
            "-n", "vigil", "--reuse-values", "--set-string", f"agentWorker.image.tag={missing_tag}",
            "--atomic", "--wait", "--timeout", "90s", check=False,
        )
        runtime.kubectl("a", "rollout", "status", "deployment/vigil-agent-worker", "-n", "vigil", "--timeout=240s")
        after_history = helm_history()
        after_image = worker_image("a")

        forwards = runtime.start_forwards()
        credentials = runtime.credentials()
        tokens: dict[str, str] = {}
        for name in ("a", "b"):
            tokens[name], _ = runtime.bootstrap_and_login(runtime.TARGETS[name], credentials[name])
        outcomes: dict[str, Any] = {}
        for name in ("a", "b"):
            target = runtime.TARGETS[name]
            status, started = runtime.request(
                target.base_url, "POST", "/api/v2/agent-runs",
                {"workflow_id":"triage-v1", "finding_ids":["qualification-collision"],
                 "prompt":f"post-rollback tenant {name} control"}, token=tokens[name],
            )
            if status != 202:
                raise RuntimeError(f"tenant {name} post-rollback admission failed: {status} {started}")
            outcomes[name] = runtime.wait_run(target, tokens[name], started["run_id"])

        before_revision = int(before_history[-1]["revision"])
        after_revision = int(after_history[-1]["revision"])
        rollback_entries = after_history[len(before_history):]
        report["helm"] = {
            "before_revision": before_revision,
            "after_revision": after_revision,
            "injected_returncode": injected.returncode,
            "new_entries": rollback_entries,
            "before_image": before_image,
            "after_image": after_image,
        }
        report["controls"] = outcomes
        report["assertions"]["T11_failed_rollout_is_rolled_back_atomically"] = (
            injected.returncode != 0 and after_revision > before_revision
            and any(entry["status"] == "failed" for entry in rollback_entries)
            and after_history[-1]["status"] == "deployed"
            and after_image == before_image
        )
        report["assertions"]["T11_tenant_a_executes_after_rollback"] = outcomes["a"]["status"] == "succeeded"
        report["assertions"]["T12_tenant_b_executes_during_independent_rollback"] = outcomes["b"]["status"] == "succeeded"
        report["result"] = "passed" if all(report["assertions"].values()) else "failed"
        return 0 if report["result"] == "passed" else 1
    except Exception as exc:
        report["result"] = "failed"
        report["error"] = str(exc)
        return 1
    finally:
        if forwards:
            runtime.stop_forwards(forwards)
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        path = EVIDENCE / "rollback.json"
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"result":report.get("result"), "evidence":str(path), "assertions":report["assertions"]}, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
