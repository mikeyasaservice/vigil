# Phase 2 local qualification environment

This Pulumi Go project creates a local release-qualification environment for two synthetic tenants. It
expects a disposable kind cluster with Cilium installed. Pulumi creates a separate
LocalStack 4.8.1 instance and synthetic model endpoint in each tenant namespace. It
does not create or discover real AWS resources.

It is evidence for repeatable data-plane behavior, not a substitute for a production
cluster, host, cloud IAM, backup, or incident-recovery qualification.

The qualification runner must create a fresh kind cluster named `vigil-phase2`, install
Cilium, start isolated LocalStack state, and then run:

```sh
./scripts/preflight.sh
./scripts/provision.sh
export PULUMI_STATE_DIR="${TMPDIR:-/tmp}/vigil-phase2-pulumi-state"
pulumi login "file://$PULUMI_STATE_DIR"
pulumi stack init phase2-local
pulumi config set cluster vigil-phase2
pulumi config set kubeContext kind-vigil-phase2
pulumi config set --secret kubeconfig "$(cat /path/to/vigil-phase2-kubeconfig)"
./scripts/preview.sh
./scripts/provision-pulumi.sh
./scripts/seed.sh
./scripts/test.sh
./scripts/cleanup.sh
```

`kind-config.yaml` disables the default kind CNI so Cilium owns policy
enforcement. The scripts use only the explicitly named `vigil-phase2` cluster;
cleanup never targets another kind context.

`preview.sh`, `provision-pulumi.sh`, and `cleanup.sh` always select the isolated
local `file://` backend at `PULUMI_STATE_DIR` (or the displayed temporary default).
Set `PULUMI_CONFIG_PASSPHRASE` or use Pulumi's interactive prompt when creating
the secret-marked kubeconfig entry; never commit the generated stack YAML.

All LocalStack credentials are synthetic. Each instance exposes only S3 and Secrets
Manager, and its state is tenant-local. The connector has the only application
egress path to it; the worker is denied. The seeded emulator state and successful
connectivity probe are network-policy evidence; they are not evidence for a complete
AWS SDK adapter, AWS IAM, or host isolation.

The namespaces are labeled `vigil.io/tenant=a|b`. The generated egress policies
deny all traffic until the test overlay adds exact peer rules. The test runner
must verify both allowed and denied probes from actual worker pods, then delete
only the named stack and kind cluster.
