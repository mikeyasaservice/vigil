# Multi-tenant database strategy

Decision D02: the initial managed customer gets a dedicated PostgreSQL **instance**,
database, encryption key and backup repository. The baseline snapshot contains 55
tables and none has a `tenant_id`, `organization_id` or `org_id` column. This is source
inventory evidence, not a live-database inspection; see [the audit](vigil-phase1-audit.md).

## Options

| Layout | Isolation and cost | Decision |
|---|---|---|
| Instance per tenant | Separate failure, runtime login, backup, key and restore boundaries; highest fixed cost | MVP and dedicated/BYOC default |
| Database per tenant, shared instance | Strong database grants but shared administrator, WAL, availability, resource and usually storage key | First SaaS cost experiment after capacity/restore proof |
| Schema per tenant | Search-path and privilege mistakes; shared connection identity/backup; migration fanout | Avoid as primary security boundary |
| Shared tables with RLS | Lowest fixed storage overhead; greatest policy, migration and bypass burden | Deferred; opt-in only after T14 and threat review |

Dedicated databases still require authenticated tenant routing; a connection resolver
with access to every tenant can leak everything if tricked into selecting the wrong
DSN. Keep runtime identities limited to one deployment. Separate migration, backup and
application roles; remove schema creation from the ordinary runtime. Administrative
credentials must never enter agent environments or normal request connection pools.

## If shared tables are proposed

Require a non-null immutable tenant key on every tenant-owned root, child, join, audit,
lease, queue-support and evaluation table. Define primary/unique/foreign keys with
tenant scope, so a child row cannot reference another tenant even when its object ID
is valid. Global reference tables are separately owned and read-only; customer additions
go to tenant tables. Views, materialized views, functions, triggers, imports, exports,
bulk jobs and search indexes are part of the review, not exceptions.

Enable **and force** RLS on tenant tables, with both read predicates and write checks,
default denial when identity is missing, and separately reviewed role grants. Runtime
roles must be `NOSUPERUSER NOBYPASSRLS`, non-owners, unable to alter policies, assume
migration roles, create unsafe functions, or change ownership. Restrict `TRUNCATE`,
`REFERENCES`, security-definer functions and schema creation. PostgreSQL superusers and
`BYPASSRLS` roles bypass RLS; forcing RLS does not constrain them. Owners ordinarily
bypass it too. [PostgreSQL row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

A session variable such as `app.tenant_id` is not proof of identity if the runtime can
set it arbitrarily. Preferred shared-instance prototype: a distinct tenant login with
non-escalatable role mapping and pools keyed by authenticated binding. If a trusted
query proxy establishes transaction context, prove that untrusted SQL cannot set or
override it and that the proxy cannot be confused into routing foreign credentials.
Do not approve a generic all-tenant login plus `SET tenant_id` as isolation from a
compromised application or SQL injection.

Transactions must begin with authenticated scope; transaction pooling must not retain
state across tenants. Test concurrent A/B reuse, cancellation, failed transactions,
prepared statements, ORM lazy loads and background tasks. Disallow arbitrary
`search_path`; use qualified relations and constrained function search paths. Constraint
errors, aggregates and pagination can disclose foreign existence even when rows are
hidden, so normalize unauthorized object responses.

Tenant-aware enforcement stays in repositories/services in addition to RLS. SQL policies
are defense in depth against omitted filters, not a substitute for operation permission
or capability authorization. Migration and backup roles are deliberately privileged and
must run as scoped, audited jobs with explicit target verification and no data export
to the fleet control plane.

## Migration and validation

Bind an existing instance to one verified tenant; never infer ownership from username,
agent labels or Azure integration tenant IDs. Quarantine mixed/ambiguous data for owner
resolution. Before any shared-row migration, enumerate all tables using both live
catalog and checked-in schema, backfill ownership, validate foreign keys and RLS in a
shadow copy, then enforce non-null constraints. Test raw SQL with the actual runtime
role, including denied writes, joins, views, indirect functions and attempted role
escalation. A passed API test alone cannot validate database isolation.

Backups/restore must preserve tenant labels and recreate policies/grants; verify their
integrity before serving reads. Do not restore one tenant by rewinding a shared cluster
and losing another tenant's writes. Shared-instance point-in-time recovery restores to
a quarantined cluster, then extracts only the authorized tenant and replays an audited
cutover. [Backup and recovery](../operations/backup-and-recovery.md).
