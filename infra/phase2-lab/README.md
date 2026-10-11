# Phase 2 disposable lab

This Pulumi Go project creates the policy shell for two synthetic tenants. It
expects a disposable kind cluster with Cilium installed and a LocalStack
4.8.1 endpoint at `http://127.0.0.1:4567`. It does not create or discover real AWS
resources.

The lab runner must create a fresh kind cluster named `vigil-phase2`, install
Cilium, start isolated LocalStack state, and then run:

```sh
./scripts/preflight.sh
./scripts/provision.sh
pulumi stack init phase2-local
pulumi config set cluster vigil-phase2
pulumi config set kubeContext kind-vigil-phase2
pulumi config set --secret kubeconfig "$(cat /path/to/vigil-phase2-kubeconfig)"
pulumi config set localstackEndpoint http://127.0.0.1:4567
./scripts/preview.sh
./scripts/provision-pulumi.sh
LOCALSTACK_ENDPOINT=http://127.0.0.1:4567 ./scripts/seed.sh
./scripts/test.sh
./scripts/cleanup.sh
```

`kind-config.yaml` disables the default kind CNI so Cilium owns policy
enforcement. The scripts use only the explicitly named `vigil-phase2` cluster;
cleanup never targets another kind context.

All LocalStack credentials are synthetic. The AWS SDK/provider configuration
must set explicit service endpoints, dummy credentials, and disabled ambient
credential discovery. A successful LocalStack operation is adapter evidence;
it is not AWS IAM or host-isolation evidence.

The namespaces are labeled `vigil.io/tenant=a|b`. The generated egress policies
deny all traffic until the test overlay adds exact peer rules. The test runner
must verify both allowed and denied probes from actual worker pods, then delete
only the named stack and kind cluster.
