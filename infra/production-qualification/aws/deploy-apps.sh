#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/../../.." && pwd)"
work_root="${VIGIL_AWS_QUALIFICATION_ROOT:-/tmp/vigil-aws-qualification}"
source_profile="${AWS_PROFILE:-pulumi}"
region="${AWS_REGION:-us-east-1}"
image_tag="${VIGIL_QUALIFICATION_IMAGE_TAG:-qual-20261011-r1}"
backend_image_tag="${VIGIL_QUALIFICATION_BACKEND_IMAGE_TAG:-$image_tag}"
agent_image_tag="${VIGIL_QUALIFICATION_AGENT_IMAGE_TAG:-$image_tag}"
connector_image_tag="${VIGIL_QUALIFICATION_CONNECTOR_IMAGE_TAG:-$image_tag}"
reasoner_image_tag="${VIGIL_QUALIFICATION_REASONER_IMAGE_TAG:-$image_tag}"
spire_version="0.30.3"
spire_crds_version="0.6.1"
external_secrets_version="2.12.0"
helm_root="$work_root/helm"

export AWS_REGION="$region" AWS_DEFAULT_REGION="$region" AWS_EC2_METADATA_DISABLED=true

ensure_helm_repositories() {
  mkdir -p "$helm_root/config" "$helm_root/cache"
  export HELM_REPOSITORY_CONFIG="$helm_root/config/repositories.yaml"
  export HELM_REPOSITORY_CACHE="$helm_root/cache"
  helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/ --force-update >/dev/null
  helm repo add external-secrets https://charts.external-secrets.io --force-update >/dev/null
  helm repo update >/dev/null
}

configure_profiles() {
  local source_config="${AWS_CONFIG_FILE:-${HOME}/.aws/config}" generated="$work_root/aws-config"
  [[ -r "$source_config" ]] || { echo "AWS config is not readable: $source_config" >&2; return 1; }
  if ! grep -q '^\[profile vigil-tenant-a\]$' "$source_config"; then
    cp "$source_config" "$generated"
    for tenant in a b; do
      local role external
      role="$(jq -er --arg tenant "$tenant" '.roleArns[$tenant]' "$work_root/bootstrap/outputs.json")"
      external="$(jq -er --arg tenant "$tenant" '.externalIds[$tenant]' "$work_root/bootstrap/outputs.json")"
      cat >>"$generated" <<EOF

[profile vigil-tenant-$tenant]
role_arn = $role
source_profile = $source_profile
external_id = $external
region = $region
EOF
    done
    chmod 600 "$generated"
  else
    cp "$source_config" "$generated"
  fi
  export AWS_CONFIG_FILE="$generated"
}

prepare_kubeconfig() {
  local tenant="$1" root cluster
  root="$work_root/tenant-$tenant"
  cluster="$(jq -er .clusterName "$root/outputs.json")"
  AWS_PROFILE="vigil-tenant-$tenant" aws eks update-kubeconfig \
    --name "$cluster" --alias "vigil-qual-$tenant" --kubeconfig "$root/kubeconfig" >/dev/null
  chmod 600 "$root/kubeconfig"
}

render_tenant() {
  local tenant="$1" subnet_cidrs="$2" root outputs values store spire_values
  root="$work_root/tenant-$tenant"
  outputs="$root/outputs.json"
  values="$root/vigil-values.yaml"
  store="$root/secret-store.yaml"
  spire_values="$root/spire-values.yaml"
  local deployment incarnation database secret role backend agent connector reasoner daemon trust_domain
  deployment="$(jq -er .deploymentId "$outputs")"
  incarnation="$(jq -er .incarnation "$root/manifest.json")"
  database="$(jq -er .databaseEndpoint "$outputs")"
  secret="$(jq -er .runtimeSecretArn "$outputs")"
  role="$(jq -er .externalSecretsRoleArn "$outputs")"
  backend="$(jq -er .imageRepositories.backend "$outputs")"
  agent="$(jq -er .imageRepositories.agent "$outputs")"
  connector="$(jq -er .imageRepositories.connector "$outputs")"
  reasoner="$(jq -er .imageRepositories.reasoner "$outputs")"
  daemon="$(jq -er .imageRepositories.daemon "$outputs")"
  trust_domain="qual-$tenant.autobot.internal"

  cat >"$spire_values" <<EOF
global:
  spire:
    clusterName: $deployment
    trustDomain: $trust_domain
    caSubject:
      country: US
      organization: Vigil
      commonName: $deployment
    persistence:
      storageClass: gp2
    namespaces:
      create: false
    recommendations:
      enabled: true
      prometheus: false
spiffe-oidc-discovery-provider:
  enabled: false
spire-server:
  resources:
    requests: { cpu: 100m, memory: 256Mi }
    limits: { cpu: 500m, memory: 512Mi }
  controllerManager:
    resources:
      requests: { cpu: 50m, memory: 128Mi }
      limits: { cpu: 250m, memory: 256Mi }
spire-agent:
  resources:
    requests: { cpu: 50m, memory: 128Mi }
    limits: { cpu: 250m, memory: 256Mi }
EOF

  cat >"$store" <<EOF
apiVersion: external-secrets.io/v1
kind: ClusterSecretStore
metadata:
  name: vigil-aws-secrets
  labels:
    vigil.io/deployment-id: $deployment
spec:
  provider:
    aws:
      service: SecretsManager
      region: $region
EOF

  cat >"$values" <<EOF
global:
  imagePullPolicy: IfNotPresent
backend:
  replicaCount: 1
  image: { repository: $backend, tag: $backend_image_tag }
  resources:
    requests: { cpu: 150m, memory: 384Mi }
    limits: { cpu: 1000m, memory: 1Gi }
daemon:
  enabled: false
  image: { repository: $daemon, tag: $image_tag }
llmWorker:
  enabled: false
agentServe:
  enabled: false
agentWorker:
  enabled: true
  replicaCount: 1
  image: { repository: $agent, tag: $agent_image_tag }
postgresql:
  enabled: false
  external:
    host: $database
    port: 5432
    database: vigil
    username: vigil_admin
    existingSecret: vigil-secrets
    existingSecretKey: POSTGRES_PASSWORD
    sslRequired: true
redis:
  enabled: false
  external:
    existingSecret: vigil-secrets
    existingSecretKey: REDIS_URL
secrets:
  existingSecret: ""
  externalSecret:
    enabled: true
    refreshInterval: 15m
    secretStoreRef: { name: vigil-aws-secrets, kind: ClusterSecretStore }
    dataFrom:
      - extract: { key: $secret }
config:
  DEV_MODE: "false"
  SECRETS_BACKEND: dotenv
  ENABLE_KEYRING: "false"
  VIGIL_COOKIE_SECURE: "true"
  VIGIL_CSRF_ENABLED: "true"
managedExecution:
  enabled: true
  deploymentId: $deployment
  deploymentIncarnation: $incarnation
  authIssuer: urn:autobot:auth:$deployment
  authAudience: vigil-managed-api
  capabilities: get_finding,case_records,recall_entity
  trustDomain: $trust_domain
  trustSecretName: vigil-secrets
  security:
    replicaCount: 1
  connector:
    replicaCount: 1
    image: { repository: $connector, tag: $connector_image_tag }
    builtinTools: get_finding,case_records,recall_entity
    bindingsJson: '{}'
  reasoner:
    replicaCount: 1
    image: { repository: $reasoner, tag: $reasoner_image_tag }
networkPolicies:
  enabled: true
  managedExecution: true
  managedDataServiceCIDRs:
$(printf '%s\n' "$subnet_cidrs" | tr ',' '\n' | sed 's/^/    - /')
EOF
  chmod 600 "$values" "$store" "$spire_values"
  printf '%s\n' "$role" >"$root/external-secrets-role-arn"
  chmod 600 "$root/external-secrets-role-arn"
}

install_dependencies() {
  local tenant="$1" root role kube
  root="$work_root/tenant-$tenant"
  role="$(cat "$root/external-secrets-role-arn")"
  kube="$root/kubeconfig"
  AWS_PROFILE="vigil-tenant-$tenant" KUBECONFIG="$kube" helm upgrade --install spire-crds spiffe/spire-crds \
    --version "$spire_crds_version" --namespace spire-server --create-namespace \
    --rollback-on-failure --wait --timeout 5m
  AWS_PROFILE="vigil-tenant-$tenant" KUBECONFIG="$kube" kubectl create namespace spire-system --dry-run=client -o yaml | \
    AWS_PROFILE="vigil-tenant-$tenant" KUBECONFIG="$kube" kubectl apply -f -
  AWS_PROFILE="vigil-tenant-$tenant" KUBECONFIG="$kube" helm upgrade --install spire spiffe/spire \
    --version "$spire_version" --namespace spire-server --create-namespace \
    --values "$root/spire-values.yaml" --rollback-on-failure --wait --timeout 15m
  AWS_PROFILE="vigil-tenant-$tenant" KUBECONFIG="$kube" helm upgrade --install external-secrets external-secrets/external-secrets \
    --version "$external_secrets_version" --namespace external-secrets --create-namespace \
    --set installCRDs=true --set serviceAccount.name=external-secrets \
    --set-string "serviceAccount.annotations.eks\.amazonaws\.com/role-arn=$role" \
    --rollback-on-failure --wait --timeout 10m
  AWS_PROFILE="vigil-tenant-$tenant" KUBECONFIG="$kube" kubectl apply -f "$root/secret-store.yaml"
}

install_vigil() {
  local tenant="$1" root kube
  root="$work_root/tenant-$tenant"
  kube="$root/kubeconfig"
  AWS_PROFILE="vigil-tenant-$tenant" KUBECONFIG="$kube" kubectl create namespace vigil --dry-run=client -o yaml | \
    AWS_PROFILE="vigil-tenant-$tenant" KUBECONFIG="$kube" kubectl apply -f -
  helm lint "$repo_dir/infra/helm/vigil" --values "$root/vigil-values.yaml"
  helm template vigil "$repo_dir/infra/helm/vigil" --namespace vigil --values "$root/vigil-values.yaml" >"$root/vigil-rendered.yaml"
  AWS_PROFILE="vigil-tenant-$tenant" KUBECONFIG="$kube" helm upgrade --install vigil "$repo_dir/infra/helm/vigil" \
    --namespace vigil --values "$root/vigil-values.yaml" --rollback-on-failure --wait --timeout 20m
}

status_tenant() {
  local tenant="$1" root
  root="$work_root/tenant-$tenant"
  AWS_PROFILE="vigil-tenant-$tenant" KUBECONFIG="$root/kubeconfig" kubectl get pods -A -o wide
  AWS_PROFILE="vigil-tenant-$tenant" KUBECONFIG="$root/kubeconfig" kubectl get externalsecret,clustersecretstore -A
}

configure_profiles

case "${1:-deploy}" in
  render)
    render_tenant a '10.64.16.0/20,10.64.32.0/20'
    render_tenant b '10.80.16.0/20,10.80.32.0/20'
    ;;
  dependencies)
    for tenant in a b; do prepare_kubeconfig "$tenant"; done
    ensure_helm_repositories
    render_tenant a '10.64.16.0/20,10.64.32.0/20'
    render_tenant b '10.80.16.0/20,10.80.32.0/20'
    install_dependencies a
    install_dependencies b
    ;;
  apps)
    for tenant in a b; do prepare_kubeconfig "$tenant"; done
    install_vigil a
    install_vigil b
    ;;
  deploy)
    for tenant in a b; do prepare_kubeconfig "$tenant"; done
    ensure_helm_repositories
    render_tenant a '10.64.16.0/20,10.64.32.0/20'
    render_tenant b '10.80.16.0/20,10.80.32.0/20'
    install_dependencies a
    install_dependencies b
    install_vigil a
    install_vigil b
    ;;
  status)
    for tenant in a b; do prepare_kubeconfig "$tenant"; done
    status_tenant a
    status_tenant b
    ;;
  *) echo "usage: $0 [render|dependencies|apps|deploy|status]" >&2; exit 2 ;;
esac
