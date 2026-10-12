import { describe, expect, it, vi } from "vitest";

import { managedDependenciesReady, workerReady } from "../../worker.js";

function worker(running: boolean, status: string) {
  return {
    isRunning: () => running,
    client: Promise.resolve({ status }),
  };
}

describe("workerReady", () => {
  it("requires both the queue and execution ledger", async () => {
    const pool = { query: vi.fn().mockResolvedValue({ rows: [] }) };
    await expect(workerReady(worker(true, "ready") as never, pool as never)()).resolves.toBe(true);
    expect(pool.query).toHaveBeenCalledWith("SELECT 1 FROM agent_run_leases LIMIT 0");
  });

  it("fails closed when the execution ledger is unavailable", async () => {
    const pool = { query: vi.fn().mockRejectedValue(new Error("database unavailable")) };
    await expect(workerReady(worker(true, "ready") as never, pool as never)()).resolves.toBe(false);
  });
});

describe("managed worker dependency readiness", () => {
  it("checks the security and reasoner paths through the local identity proxy", async () => {
    vi.stubEnv("VIGIL_EXECUTION_PROFILE", "managed");
    vi.stubEnv("VIGIL_MANAGED_GATEWAY_BASE_URL", "http://127.0.0.1:15001/v1");
    vi.stubEnv("VIGIL_MANAGED_REASONER_URL", "http://127.0.0.1:15002/v1/evaluate");
    const fetcher = vi.fn().mockResolvedValue({ ok: true });

    await expect(managedDependenciesReady(fetcher)).resolves.toBe(true);
    expect(fetcher.mock.calls.map(([url]) => url)).toEqual([
      "http://127.0.0.1:15001/healthz",
      "http://127.0.0.1:15002/healthz",
    ]);
    vi.unstubAllEnvs();
  });

  it("fails closed when either managed path is unavailable", async () => {
    vi.stubEnv("VIGIL_EXECUTION_PROFILE", "managed");
    const fetcher = vi.fn()
      .mockResolvedValueOnce({ ok: true })
      .mockResolvedValueOnce({ ok: false });

    await expect(managedDependenciesReady(fetcher)).resolves.toBe(false);
    vi.unstubAllEnvs();
  });

  it("does not impose managed dependencies on the standalone profile", async () => {
    vi.stubEnv("VIGIL_EXECUTION_PROFILE", "standalone");
    const fetcher = vi.fn();

    await expect(managedDependenciesReady(fetcher)).resolves.toBe(true);
    expect(fetcher).not.toHaveBeenCalled();
    vi.unstubAllEnvs();
  });
});
