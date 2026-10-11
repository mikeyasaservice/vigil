import { createPublicKey, verify as verifySignature } from "node:crypto";
import type { ManagedQueueEnvelope, RunJob } from "../contracts/job.js";

export class ManagedAdmissionError extends Error {}

export interface ManagedExecutionIdentity {
  execution_id: string;
  tenant_id: string;
  deployment_id: string;
  workflow_id: string;
  workflow_digest: string;
  program_id: string;
  program_digest: string;
  worker_key_id: string;
  capabilities: readonly string[];
  policy_version: string;
  revocation_epoch: number;
  expires_at: string;
}

function canonical(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(value, (_key, held) => {
    if (held && typeof held === "object" && !Array.isArray(held)) {
      return Object.fromEntries(Object.entries(held).sort(([a], [b]) => a.localeCompare(b)));
    }
    return held;
  }));
}

function decodeBase64Url(value: string): Buffer {
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/** Verify a signed admission before resolving any workflow or opening the ledger. */
export function verifyManagedEnvelope(envelope: ManagedQueueEnvelope, now = Date.now()): void {
  if (envelope.schema_version !== 2 || !["start", "resume"].includes(envelope.reason)) {
    throw new ManagedAdmissionError("unsupported managed queue envelope");
  }
  const authorityKey = process.env["VIGIL_MANAGED_AUTHORITY_PUBLIC_KEY"] ?? "";
  if (authorityKey === "") throw new ManagedAdmissionError("managed authority key is not configured");
  const deploymentId = process.env["VIGIL_DEPLOYMENT_ID"] ?? "";
  const admission = envelope.admission;
  const context = admission["context"] as Record<string, unknown> | undefined;
  if (!context || context["deployment_id"] !== deploymentId) {
    throw new ManagedAdmissionError("managed job targets another deployment");
  }
  const expiresAt = Date.parse(String(admission["expires_at"] ?? ""));
  if (!Number.isFinite(expiresAt) || expiresAt <= now) throw new ManagedAdmissionError("managed admission expired");
  const signed = {
    schema_version: envelope.schema_version,
    admission,
    execution_id: envelope.execution_id,
    reason: envelope.reason,
    references: envelope.references,
  };
  const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), decodeBase64Url(authorityKey)]), format: "der", type: "spki" });
  if (!verifySignature(null, canonical(signed), key, decodeBase64Url(envelope.signature))) {
    throw new ManagedAdmissionError("managed admission signature is invalid");
  }
}

export function verifyManagedJob(job: RunJob): void {
  if (job.managed === undefined) return;
  verifyManagedEnvelope(job.managed);
  if (job.managed.execution_id.length < 16) throw new ManagedAdmissionError("managed execution id is invalid");
}

export function claimManagedExecution(job: RunJob): ManagedExecutionIdentity | null {
  if (job.managed === undefined) return null;
  verifyManagedEnvelope(job.managed);
  const workerKeyId = process.env["VIGIL_WORKER_KEY_ID"] ?? "";
  if (workerKeyId === "") throw new ManagedAdmissionError("managed worker key is not configured");
  const admission = job.managed.admission;
  const context = admission["context"] as Record<string, unknown>;
  const capabilities = (process.env["VIGIL_MANAGED_CAPABILITIES"] ?? "findings.read")
    .split(",").map((value) => value.trim()).filter(Boolean);
  return {
    execution_id: job.managed.execution_id,
    tenant_id: String(context["tenant_id"]),
    deployment_id: String(context["deployment_id"]),
    workflow_id: String(admission["workflow_id"]),
    workflow_digest: String(admission["workflow_digest"]),
    program_id: String(admission["program_id"]),
    program_digest: String(admission["program_digest"]),
    worker_key_id: workerKeyId,
    capabilities,
    policy_version: String(context["policy_version"]),
    revocation_epoch: Number(admission["revocation_epoch"]),
    expires_at: String(admission["expires_at"]),
  };
}
