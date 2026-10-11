import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import canonicalize from "canonicalize";
import type { ManagedQueueEnvelope, RunJob } from "../contracts/job.js";

export class ManagedAdmissionError extends Error {}

async function denialCode(response: Response): Promise<string> {
  try {
    const value = await response.json() as { detail?: { code?: unknown } | unknown };
    if (typeof value.detail === "object" && value.detail !== null &&
        typeof (value.detail as { code?: unknown }).code === "string") {
      return (value.detail as { code: string }).code;
    }
  } catch {
    // A proxy-generated or older error body has no trusted structured code.
  }
  return "claim_denied";
}

export interface ManagedExecutionIdentity {
  execution_id: string;
  tenant_id: string;
  deployment_id: string;
  workflow_id: string;
  workflow_digest: string;
  program_id: string;
  program_digest: string;
  workload_spiffe_id: string;
  /** Deprecated compatibility alias; equals workload_spiffe_id. */
  worker_key_id: string;
  capabilities: readonly string[];
  policy_version: string;
  revocation_epoch: number;
  issued_at: string;
  expires_at: string;
  jti: string;
  attestation: string;
}

function canonical(value: unknown): Buffer {
  const encoded = canonicalize(value);
  if (encoded === undefined) throw new ManagedAdmissionError("managed JSON is outside the canonical domain");
  return Buffer.from(encoded, "utf8");
}

// Schema v2 used the original local stable serializer. It remains verification
// only so already queued ASCII work can drain during the coordinated v3 cutover.
function legacyCanonical(value: unknown): Buffer {
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

export function managedDigest(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

function decodeBase64Url(value: string): Buffer {
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/** Verify a signed admission before resolving any workflow or opening the ledger. */
export function verifyManagedEnvelope(envelope: ManagedQueueEnvelope, now = Date.now()): void {
  if (![2, 3].includes(envelope.schema_version) || !["start", "resume"].includes(envelope.reason)) {
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
  if (envelope.schema_version === 3) {
    for (const key of ["workflow_id", "workflow_digest", "program_id", "program_digest", "finding_reference_digest"] as const) {
      if (!envelope.references[key]) throw new ManagedAdmissionError("managed exact-work binding is incomplete");
    }
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
  const bytes = envelope.schema_version === 3 ? canonical(signed) : legacyCanonical(signed);
  if (!verifySignature(null, bytes, key, decodeBase64Url(envelope.signature))) {
    throw new ManagedAdmissionError("managed admission signature is invalid");
  }
}

export function verifyManagedJob(job: RunJob): void {
  if (process.env["VIGIL_EXECUTION_PROFILE"] === "managed" && job.managed === undefined) {
    throw new ManagedAdmissionError("managed jobs require a signed admission envelope");
  }
  if (job.managed === undefined) return;
  verifyManagedEnvelope(job.managed);
  if (job.reason !== job.managed.reason) {
    throw new ManagedAdmissionError("managed envelope reason does not match the queue job");
  }
  if (job.managed.execution_id.length < 16) throw new ManagedAdmissionError("managed execution id is invalid");
  if (job.managed.references["run_id"] !== job.run_id || job.managed.references["run_kind"] !== job.run_kind) {
    throw new ManagedAdmissionError("managed envelope does not match the queue job");
  }
  const admission = job.managed.admission;
  if (job.reason === "start") {
    const requestDigest = managedDigest(job.request);
    if (job.managed.references["request_digest"] !== requestDigest) {
      throw new ManagedAdmissionError("managed envelope does not match the run request");
    }
    if (job.managed.schema_version === 3 &&
        job.managed.references["finding_reference_digest"] !== managedDigest({ finding_ids: job.request.finding_ids ?? [] })) {
      throw new ManagedAdmissionError("managed envelope does not match the admitted findings");
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
  const capabilities = (process.env["VIGIL_MANAGED_CAPABILITIES"] ?? "")
    .split(",").map((value) => value.trim()).filter(Boolean);
  return {
    execution_id: job.managed.execution_id,
    tenant_id: String(context["tenant_id"]),
    deployment_id: String(context["deployment_id"]),
    workflow_id: String(admission["workflow_id"]),
    workflow_digest: String(admission["workflow_digest"]),
    program_id: String(admission["program_id"]),
    program_digest: String(admission["program_digest"]),
    workload_spiffe_id: workerKeyId,
    worker_key_id: workerKeyId,
    capabilities,
    policy_version: String(context["policy_version"]),
    revocation_epoch: Number(admission["revocation_epoch"]),
    issued_at: String(admission["issued_at"]),
    expires_at: String(admission["expires_at"]),
    jti: "local-claim-disabled",
    attestation: "",
  };
}

/** Claim through the tenant-local security service; managed workers do not self-issue identities. */
export async function claimManagedExecutionFromService(job: RunJob): Promise<ManagedExecutionIdentity | null> {
  if (job.managed === undefined) return null;
  verifyManagedJob(job);
  const workloadId = process.env["VIGIL_WORKER_SPIFFE_ID"] ?? "";
  if (workloadId === "") throw new ManagedAdmissionError("managed workload identity is not configured");
  const response = await fetch(process.env["VIGIL_MANAGED_CLAIM_URL"] ?? "http://127.0.0.1:15001/v1/claim", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ envelope: job.managed, capabilities: (process.env["VIGIL_MANAGED_CAPABILITIES"] ?? "").split(",").map((value) => value.trim()).filter(Boolean) }),
  });
  if (!response.ok) {
    const code = await denialCode(response);
    throw new ManagedAdmissionError(`managed execution claim denied (${response.status}, ${code})`);
  }
  const value = await response.json();
  if (typeof value !== "object" || value === null) {
    throw new ManagedAdmissionError("managed claim returned an invalid identity");
  }
  const identity = value as Record<string, unknown>;
  for (const key of ["execution_id", "tenant_id", "deployment_id", "workload_spiffe_id", "jti", "attestation"] as const) {
    if (typeof identity[key] !== "string" || identity[key] === "") {
      throw new ManagedAdmissionError("managed claim returned an invalid identity");
    }
  }
  if (identity["workload_spiffe_id"] !== workloadId) {
    throw new ManagedAdmissionError("managed claim returned a foreign worker identity");
  }
  return value as ManagedExecutionIdentity;
}

export async function updateManagedExecutionStatus(
  identity: ManagedExecutionIdentity,
  status: "running" | "retrying" | "waiting_approval" | "succeeded" | "failed",
  pending?: { checkpoint_id: string; tool: string; args: string },
): Promise<void> {
  const response = await fetch(process.env["VIGIL_MANAGED_STATUS_URL"] ?? "http://127.0.0.1:15001/v1/status", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      execution_id: identity.execution_id,
      claim_token: identity.jti,
      attestation: identity.attestation,
      status,
      ...(pending === undefined ? {} : { pending }),
    }),
  });
  if (!response.ok) throw new ManagedAdmissionError(`managed execution status update denied (${response.status})`);
}
