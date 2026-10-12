# Real AWS qualification harness

This harness creates two expiring dedicated environments in separate VPCs in the
currently bound development account. It uses the `pulumi` AWS profile only to create
and assume tenant-specific deployment roles. Runtime pods never receive that profile.

The local work root defaults to `/tmp/vigil-aws-qualification` and contains encrypted
Pulumi state plus the generated external IDs. It must remain mode `0700` and must not be
committed. The default EKS API allowlist is the qualifying host's current `/32`; override
`VIGIL_CONTROL_PLANE_CIDR` when the host address changes.

Commands are intentionally split into saved preview, apply, and offboarding stages:

```bash
export VIGIL_AWS_ACCOUNT_ID='<authorized-development-account-id>'
export VIGIL_AWS_TRUSTED_PRINCIPAL_ARN='<approved-deployer-role-arn>'
export VIGIL_CONTROL_PLANE_CIDR='<qualifying-host-public-ip>/32'
export AUTOBOT_AWS_ACCOUNT_ID="$VIGIL_AWS_ACCOUNT_ID"
./infra/production-qualification/aws/qualify.sh preview
./infra/production-qualification/aws/qualify.sh apply
./infra/production-qualification/aws/qualify.sh offboard
```

Offboarding first changes the trusted lifecycle state so Pulumi can remove deletion
protection and resource protection, then destroys both tenant stacks and the temporary
bootstrap roles. Use `offboard-a`, `offboard-b`, or `bootstrap-offboard` to resume at an
exact checkpoint after a partial failure. Every stage performs direct AWS deletion checks.
