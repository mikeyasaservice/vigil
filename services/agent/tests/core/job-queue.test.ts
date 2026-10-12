import { describe, expect, it } from "vitest";

import { RUN_QUEUE, RUN_QUEUE_PREFIX } from "../../contracts/job.js";

describe("managed queue cluster contract", () => {
  it("uses the same cluster hash tag as the Python producer", () => {
    expect(RUN_QUEUE).toBe("agent-runs");
    expect(RUN_QUEUE_PREFIX).toBe("{bull}");
  });
});
