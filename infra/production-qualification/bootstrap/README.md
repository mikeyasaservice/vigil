# Production qualification bootstrap

This project creates only the two expiring deployment roles used by the real AWS
qualification environments. It runs with the host's authenticated `pulumi` profile;
the tenant stacks do not. Each tenant stack must assume its own role with the generated
external ID. Keep the local Pulumi state outside the repository and destroy the stack
after collecting the qualification evidence.

The role policy is intentionally limited to the AWS service families used by the
ephemeral qualification stacks and to `vigil-*` workload IAM roles. It is still a
powerful infrastructure role. It is not a runtime application identity and must never
be mounted into application pods.

After both tenant stacks are offboarded, run
`./infra/production-qualification/aws/qualify.sh bootstrap-offboard`. The command
destroys both temporary deployer roles and verifies their absence directly through
IAM. If a tenant teardown stops partway through, resume with `offboard-a` or
`offboard-b`; do not reapply an already deleted tenant stack.
