# Phase 4 shared SaaS checkpoint

This Pulumi Go project provisions the executable development fixture for the
first Phase 4 sharing decision. One shared platform account contains aggregate
metering infrastructure. Tenant A and Tenant B retain separate account-scoped
KMS, S3 and SQS resources. The program exports
`dataPlaneSharing=disabled-until-iam-qualified`; customer storage, queues,
credentials, workers and reasoning state are not approved for pooling.

The LocalStack Community image does not enforce the tenant IAM policies used by
the AWS design. The qualifier therefore records direct cross-account reads as
unqualified and does not count them as isolation success. The shared services
qualified here are the PostgreSQL-backed membership, routing, quota and
aggregate-usage control paths.

Requirements: Docker, Go, Pulumi and uv.

```bash
./infra/phase4-saas/localstack/qualify.sh managed
./infra/phase4-saas/localstack/qualify.sh down
```

The first command starts loopback-only PostgreSQL and LocalStack services,
applies the Pulumi stack, runs positive A/B resource probes, reports the IAM
limitation, and runs cross-tenant and concurrent-quota database tests. Cleanup
removes only the Compose project and volumes created by this fixture. Pulumi
state remains ignored under `.local-state/` so a later run can inspect the
previous plan; use a new stack name or remove that disposable directory when a
fresh state history is required.
