# Initial infrastructure cost and operational complexity

Planning assessment dated 2026-10-11; **not a cloud quote, benchmark, capacity promise or
commercial price**. Customer demand, telemetry volume, retention, concurrency and SLA
are unknown. The initial choice favors containment and independent recovery over lowest
unit cost. Exact costs require a region-specific calculator and measured load test.

## Sizing assumptions and model

Illustrative small tenant: one region, two availability zones, 24×7 service, modest
application/worker capacity, managed PostgreSQL with HA allowance, small dedicated Redis,
100 GB primary database plus 100 GB object evidence, backups, and 100 investigations/day.
Agent concurrency, ingest rate and memory/index growth must be measured; these sizes do
not imply that a particular tenant workload fits. No GPU/self-hosted model, SIEM license,
large raw-log ingestion, cross-region DR, taxes, discounts or support labor included.

| Dedicated tenant component | Monthly USD planning allowance | Main sensitivity |
|---|---:|---|
| Dedicated application/worker VM capacity | 200–600 | CPU/memory and concurrent model/tool work |
| Dedicated managed PostgreSQL | 200–600 | HA, IO, instance size, retention |
| Dedicated Redis/queue/cache | 50–150 | Durability/replication, memory and throughput |
| Object/block storage and backups | 30–100 | Evidence size, versions, retention and retrieval |
| Network, ingress, private endpoints/NAT | 80–250 | Endpoint count, AZs and egress/processing volume |
| EKS standard-support cluster fee | 73 | 730 hours × $0.10/hour; worker resources extra |
| Local observability/key/secret service allowance | 50–150 | Log volume, metrics cardinality and key operations |
| **Tenant subtotal, excluding inference** | **683–1,923** | Sum of assumptions, not a SKU-priced estimate |

Only the EKS fee is a checked published unit price; the other rows are deliberately
rounded budget assumptions for comparing designs. AWS lists $0.10/cluster-hour under
standard Kubernetes support and additional charges for worker resources; extended
support costs more. [AWS EKS pricing](https://aws.amazon.com/eks/pricing/).
Reprice all rows and choose instance families before procurement or customer commitments.

Budget a separate illustrative **$300–1,000/month** for a small global management plane
(metadata database, API/reconciler, identity/observability and artifact delivery). This
is also an allowance, with no validated capacity. Total hosted fleet cost is approximately
`management + sum(tenant infrastructure + inference + tenant egress) + support labor`.

Inference sensitivity: 100 investigations/day × 30 days × (30,000 input + 5,000 output
tokens) = 90M input + 15M output tokens/month. Cost is `90 × input_price_per_M +
15 × output_price_per_M`. At purely illustrative $3/$15 unit assumptions this is $495
per tenant/month; these are **not** a vendor quote. Multi-agent fanout, retries,
evaluation/optimization and longer context multiply consumption. Enforce budgets and
measure actual traces before setting subscription margins.

## Mode comparison

| Mode | Cost behavior | Operational complexity | Main hidden cost |
|---|---|---|---|
| Managed dedicated MVP | Roughly linear per tenant; independent $73 cluster fee in AWS reference | Medium: repeatable templates, per-tenant backups/rollouts | Idle capacity and many upgrades; simpler incident containment |
| SaaS with tenant cells | Can share cluster fee, edge and management; dedicated worker/database costs remain | High: shared infrastructure policies and noisy-neighbor validation | Isolation regression testing, correlated outage and shared recovery |
| SaaS shared databases/processes | Potentially lower fixed cost, unquantified until measured | Very high: RLS/context/queue isolation and complex restores | Security engineering and cross-tenant incident exposure |
| BYOC | Customer pays local cloud costs similar to dedicated; provider still pays management/support | Highest: customer IAM/network/key policy variance and connectivity | Installation diagnostics, version skew, restricted support access |

For N tenant cells sharing one EKS cluster but otherwise identical dedicated resources,
the naive fixed-fee saving is `(N−1) × $73/month`. Do not justify a complex multi-customer
process redesign using this modest fee alone. Additional packing savings must be
measured against tenant-dedicated node guarantees, availability, testing and support.
BYOC transfers infrastructure billing, not the operational burden.

Initial operational readiness needs named owners for security/harness, infrastructure,
data/recovery and intelligence evaluation, plus an on-call rotation before a 24×7 SLA.
No staffing or delivery estimate is reliable without a dependency spike and customer
requirements. Track onboarding hours, upgrade failure/recovery time, cost per completed
investigation, idle resources, tenant incidents and support hours per deployment.
Use these measurements to decide when each Phase 4 sharing proposal is economically
beneficial; security gates cannot be traded for savings.
