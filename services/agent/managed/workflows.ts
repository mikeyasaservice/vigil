import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { SpecError } from "../core/spec.js";
import type { PlaybookLayers } from "../core/playbooks.js";

const ID = "triage-v1";

function paths() {
  return {
    playbook: join(import.meta.dirname, `${ID}.playbook.yaml`),
    config: join(import.meta.dirname, `${ID}.config.yaml`),
  };
}

export function managedWorkflowDigest(): string {
  const held = paths();
  const digest = createHash("sha256");
  digest.update(readFileSync(held.playbook));
  digest.update(Buffer.from([0]));
  digest.update(readFileSync(held.config));
  return `sha256:${digest.digest("hex")}`;
}

export async function managedWorkflow(reference: string, expectedDigest: string): Promise<PlaybookLayers> {
  if (reference !== `workflow:${ID}`) throw new SpecError(`managed profile does not approve ${reference}`);
  const digest = managedWorkflowDigest();
  if (digest !== expectedDigest) throw new SpecError("managed workflow artifact does not match its admission");
  const held = paths();
  return {
    playbook: readFileSync(held.playbook, "utf8"),
    config: readFileSync(held.config, "utf8"),
  };
}
