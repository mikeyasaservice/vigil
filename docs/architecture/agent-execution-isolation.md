# Agent execution isolation

The existing TypeScript harness supplies useful dispatch, budgets, leases and ledger
seams. Our independent security harness adds trusted admission, workload identity,
isolation and per-invocation authorization. DSPy runs as the reasoning component;
neither it nor an agent's requested tool list can grant capabilities.

## Isolation selection

| Option | Guarantee when correctly configured | Residual risk / cost | Use |
|---|---|---|---|
| Separate processes | Address-space isolation; separate UID can restrict files | Shared kernel and often env/files/network; weak if same credentials | Development, not cross-customer production boundary |
| Hardened containers | Namespaces, cgroups, read-only filesystem, seccomp and narrow network/identity | Shared host kernel; privileged host/cluster admin; mounted secrets | MVP, on tenant-dedicated VM/node capacity |
| MicroVMs | Guest kernel/hardware virtualization adds boundary | Host/hypervisor vulnerabilities, image/boot/network/snapshot complexity | Phase 2 spike for untrusted code/MCP; adopt before enabling high-risk extensibility |

Firecracker is a KVM-based microVM option, so portability and host support must be
assessed; use a SandboxProvider interface rather than coupling workflows to it.
[Firecracker architecture](https://firecracker-microvm.github.io/).
Dedicated workers mean no A/B credentials in one worker process or writable filesystem;
a container namespace on a shared host alone is not the dedicated-node guarantee.

## Trusted execution sequence

1. Tenant API/scheduler submits a request using an authenticated TenantContext.
   Admission checks enabled workflow and exact agent/DSPy versions, tenant policy,
   approvals, quotas, resource ownership and reserved budget.
2. Local authority signs [ExecutionIdentity](tenant-identity-context.md), journals it
   and schedules only into the bound tenant worker pool. Worker authenticates using
   workload identity; no global fleet or database-admin credentials are mounted.
3. Launch a fresh execution context with bounded CPU, memory, PIDs, wall time, disk,
   model tokens/cost, tool calls and result sizes. Context, temp files and model cache
   are execution/tenant scoped. Never reuse a dirty context for another tenant.
4. Reasoner emits typed proposals. A separate trusted gateway verifies every tool
   invocation, including nested MCP calls, memory retrieval, file/object reads and
   side effects. Bind output and async callback ownership to the same execution.
5. Gateway resolves only that integration's local credential, enforces destination and
   parameter constraints, atomically reserves budget and invocation ID, and persists
   an authorization audit event before dispatch. Audit failure blocks privileged work.
6. Cancellation/revocation marks the local execution epoch, prevents new calls, signals
   the worker, cancels pending connector requests and expires/removes grants. An external
   request already accepted may finish: reconcile its outcome, never assert it was undone.

Mandatory gateway predicates: trusted issuer/audience/signature; matching tenant,
deployment and incarnation; worker key binding; execution active; grant time validity;
policy and revocation fresh enough; exact action/resource allowed; integration owned
by tenant; required approval valid for these arguments; budgets available. Any unknown
or unverifiable required predicate denies. An LLM response cannot waive a refusal.

## Prevent bypass

Worker network policy denies direct integration, metadata-service, database-admin and
secret-store access. Only approved model gateway, capability gateway and execution
state APIs are reachable. Gateways/connectors have separate workload roles; agents
cannot modify their policy or images. Remove host PID/network, privileged mode,
Docker socket, writable host mounts and automatic service-account token mounts. Run
non-root, drop capabilities, constrain syscalls, use read-only roots and bounded scratch
storage. Containers handling MCP code get only the selected integration's credential
lease, never a copy of the backend environment.

The current tool transport's shared internal token is not an execution grant. Retain
its existing checks during migration, but require the new grant in the managed profile
without a token-only fallback. Local tool implementations must use the same gateway
or be classified as pure computation with no privileged I/O; `local` is not an exemption.
Model endpoint egress is also policy-governed: BYOC can require a local model or an
approved private/provider endpoint. Logs, tracing, provider caches and retries inherit
the data boundary.

## Phase 2 acceptance

Implement admission/context, gateway policy, tenant-local secret resolution, worker
isolation and Reasoner interfaces before enabling managed agents. Reuse upstream
ledger/projection/domain adapters; add a versioned job envelope rather than silently
changing the frozen v1 request contract. Run T02/T03/T04/T05/T06/T09/T10/T12/T13 on real
workers, broker, gateway and storage. Threat-inject model/tool output that requests a
foreign tenant or bypasses approval. Compare process/container/microVM startup latency,
memory, throughput and escape surface in a synthetic benchmark before selecting a
shared-host option. Customer code execution remains disabled until its isolation gate passes.
