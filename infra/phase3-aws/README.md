# Dedicated AWS deployment adapter

This Pulumi Go project provisions one tenant deployment. It must be invoked by the
Phase 3 reconciler with a deployment-specific stack, backend and workspace. The
program requires two files outside the repository:

- `manifestPath`: the exact signed and approved DeploymentManifest payload;
- `bindingPath`: the locally trusted account/network/state binding resolved for the
  deployment.

The manifest cannot provide an AWS account ID, role ARN, external ID, state backend
or raw network identifier. The program creates an explicit AWS provider whose
`allowedAccountIds` contains only the bound account and whose assume role comes only
from the binding file.

Do not run this project with ambient administrator credentials or a shared stack.
Every production deployment needs an isolated state backend location, secrets
provider, runner directory and scoped provisioning role.

Generate the immutable infrastructure reference with the same algorithm used by the
reconciler:

```sh
go run ./cmd/artifact-digest .
```

`binding.example.json` documents the closed trusted-binding shape. Materialize a real
binding from a secret manager into the reconciler filesystem; do not commit its
external ID, receipt key or mTLS private key.

Register the binding's RFC 8785 digest in `management_account_bindings.binding_digest`
and retain it on every admitted operation:

```sh
go run ./cmd/json-digest /run/vigil/bindings/deployment.json
```
