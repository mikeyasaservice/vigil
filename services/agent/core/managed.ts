import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
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
  jti: string;
  attestation: string;
}

function canonical(value: unknown): Buffer {
  const stable = (held: unknown): unknown => {
    if (Array.isArray(held)) return held.map(stable);
    if (held && typeof held === "object") {
      return Object.fromEntries(Object.entries(held as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => [key, stable(value)]));
    }
    return held;
  };
  return Buffer.from(JSON.stringify(stable(value)));
}

function digest(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex");
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
  if (envelope.references["request_digest"] !== admission["request_digest"] ||
      !envelope.references["run_id"] || !envelope.references["run_kind"]) {
    throw new ManagedAdmissionError("managed queue work binding is invalid");
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
  if (process.env["VIGIL_EXECUTION_PROFILE"] === "managed" && job.managed === undefined) {
    throw new ManagedAdmissionError("managed jobs require a signed admission envelope");
  }
  if (job.managed === undefined) return;
  verifyManagedEnvelope(job.managed);
  if (job.managed.execution_id.length < 16) throw new ManagedAdmissionError("managed execution id is invalid");
  if (job.managed.references["run_id"] !== job.run_id || job.managed.references["run_kind"] !== job.run_kind) {
    throw new ManagedAdmissionError("managed envelope does not match the queue job");
  }
  const admission = job.managed.admission;
  if (job.reason === "start") {
    const requestDigest = digest(job.request);
    if (job.managed.references["request_digest"] !== requestDigest) {
      throw new ManagedAdmissionError("managed envelope does not match the run request");
    }
  }
  if (job.managed.references["workflow_id"] !== undefined &&
      job.managed.references["workflow_id"] !== admission["workflow_id"]) {
    throw new ManagedAdmissionError("managed workflow binding is invalid");
  }
  for (const key of ["workflow_digest", "program_id", "program_digest"] as const) {
    if (job.managed.references[key] !== undefined && job.managed.references[key] !== admission[key]) {
      throw new ManagedAdmissionError(`managed ${key} binding is invalid`);
    }
  }
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
    jti: "local-claim-disabled",
    attestation: "",
  };
}

/** Claim through the tenant-local security service; managed workers do not self-issue identities. */
export async function claimManagedExecutionFromService(job: RunJob): Promise<ManagedExecutionIdentity | null> {
  if (job.managed === undefined) return null;
  verifyManagedJob(job);
  const workerKeyId = process.env["VIGIL_WORKER_KEY_ID"] ?? "";
  const certificate = process.env["VIGIL_WORKER_CERT_FINGERPRINT"] ?? "";
  if (workerKeyId === "" || certificate === "") throw new ManagedAdmissionError("managed worker trust material is not configured");
  const response = await fetch(process.env["VIGIL_MANAGED_CLAIM_URL"] ?? "http://security:8080/v1/claim", {
    method: "POST",
    headers: { "content-type": "application/json", "x-vigil-client-cert": certificate },
    body: JSON.stringify({ envelope: job.managed, worker_key_id: workerKeyId, capabilities: (process.env["VIGIL_MANAGED_CAPABILITIES"] ?? "findings.read").split(",").map((value) => value.trim()).filter(Boolean) }),
  });
  if (!response.ok) throw new ManagedAdmissionError(`managed execution claim denied (${response.status})`);
  const value = await response.json();
  if (typeof value !== "object" || value === null) {
    throw new ManagedAdmissionError("managed claim returned an invalid identity");
  }
  const identity = value as Record<string, unknown>;
  for (const key of ["execution_id", "tenant_id", "deployment_id", "worker_key_id", "jti", "attestation"] as const) {
    if (typeof identity[key] !== "string" || identity[key] === "") {
      throw new ManagedAdmissionError("managed claim returned an invalid identity");
    }
  }
  if (identity["worker_key_id"] !== workerKeyId) {
    throw new ManagedAdmissionError("managed claim returned a foreign worker identity");
  }
  return value as ManagedExecutionIdentity;
}
