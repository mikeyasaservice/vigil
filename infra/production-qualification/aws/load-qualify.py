#!/usr/bin/env python3
"""Measure tenant B while tenant A saturates its own managed admission/worker path."""

from __future__ import annotations

import importlib.util
import json
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("runtime_qualify", HERE / "runtime-qualify.py")
assert spec and spec.loader
runtime = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runtime
spec.loader.exec_module(runtime)

RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
EVIDENCE = runtime.ROOT / "evidence" / RUN_ID / "load.json"


def timed_read(target, token: str) -> tuple[int, float]:
    started = time.monotonic()
    status, _ = runtime.request(
        target.base_url, "GET", "/api/v1/findings/qualification-collision", token=token
    )
    return status, time.monotonic() - started


def start_run(target, token: str, index: int) -> tuple[int, dict]:
    return runtime.request(
        target.base_url,
        "POST",
        "/api/v2/agent-runs",
        {
            "workflow_id": "triage-v1",
            "finding_ids": ["qualification-collision"],
            "prompt": f"Tenant A saturation qualification {index}",
        },
        token=token,
    )


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * quantile))]


def main() -> int:
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    report: dict = {"run_id": RUN_ID, "scope": "real AWS dedicated A/B resource isolation"}
    forwards = runtime.start_forwards()
    try:
        creds = runtime.credentials()
        tokens = {
            name: runtime.bootstrap_and_login(target, creds[name])[0]
            for name, target in runtime.TARGETS.items()
        }
        baseline = [timed_read(runtime.TARGETS["b"], tokens["b"])[1] for _ in range(10)]
        with ThreadPoolExecutor(max_workers=24) as pool:
            a_futures = [
                pool.submit(start_run, runtime.TARGETS["a"], tokens["a"], index)
                for index in range(48)
            ]
            b_futures = [
                pool.submit(timed_read, runtime.TARGETS["b"], tokens["b"]) for _ in range(50)
            ]
            b_results = [future.result() for future in as_completed(b_futures)]
            a_results = [future.result() for future in as_completed(a_futures)]
        started = time.monotonic()
        status, admitted = start_run(runtime.TARGETS["b"], tokens["b"], 999)
        if status != 202:
            raise RuntimeError(f"tenant B admission failed under A load: {status} {admitted}")
        final = runtime.wait_run(runtime.TARGETS["b"], tokens["b"], admitted["run_id"])
        b_run_seconds = time.monotonic() - started
        a_statuses: dict[str, int] = {}
        for item_status, _ in a_results:
            a_statuses[str(item_status)] = a_statuses.get(str(item_status), 0) + 1
        b_latencies = [latency for status_code, latency in b_results if status_code == 200]
        report.update(
            thresholds={"tenant_b_read_p95_seconds": 2.0, "tenant_b_run_seconds": 180.0},
            baseline={"read_p95_seconds": percentile(baseline, 0.95)},
            tenant_a={"admission_status_counts": a_statuses, "requests": len(a_results)},
            tenant_b={
                "successful_reads": len(b_latencies),
                "read_p50_seconds": statistics.median(b_latencies),
                "read_p95_seconds": percentile(b_latencies, 0.95),
                "managed_run_status": final["status"],
                "managed_run_seconds": b_run_seconds,
            },
        )
        report["assertions"] = {
            "T12_A_admission_did_not_fail_open": all(code in {"202", "429"} for code in a_statuses),
            "T12_B_reads_remained_available": len(b_latencies) == 50,
            "T12_B_read_p95_within_threshold": percentile(b_latencies, 0.95) <= 2.0,
            "T12_B_investigation_completed_within_threshold": final["status"] == "succeeded"
            and b_run_seconds <= 180.0,
        }
        report["result"] = "passed" if all(report["assertions"].values()) else "failed"
    except Exception as exc:
        report.update(result="failed", error=str(exc))
    finally:
        runtime.stop_forwards(forwards)
        EVIDENCE.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"result": report["result"], "evidence": str(EVIDENCE)}))
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
