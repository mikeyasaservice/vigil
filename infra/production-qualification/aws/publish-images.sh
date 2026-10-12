#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/../../.." && pwd)"
work_root="${VIGIL_AWS_QUALIFICATION_ROOT:-/tmp/vigil-aws-qualification}"
profile="${AWS_PROFILE:-pulumi}"
region="${AWS_REGION:-us-east-1}"
account_id="${VIGIL_AWS_ACCOUNT_ID:?set VIGIL_AWS_ACCOUNT_ID to the authorized qualification account}"
tag="${1:-qual-20261011-r1}"
registry="$account_id.dkr.ecr.$region.amazonaws.com"
password_file="$work_root/ecr-password"

if (( $# > 1 )); then
  components=("${@:2}")
else
  components=(backend daemon agent connector reasoner management)
fi

dockerfile_for() {
  case "$1" in
    backend) echo "infra/docker/Dockerfile.backend" ;;
    daemon) echo "infra/docker/Dockerfile.daemon" ;;
    agent) echo "infra/docker/Dockerfile.agent" ;;
    connector) echo "infra/docker/Dockerfile.connector" ;;
    reasoner) echo "infra/docker/Dockerfile.reasoner" ;;
    management) echo "infra/docker/Dockerfile.management" ;;
    *) echo "unknown component: $1" >&2; return 1 ;;
  esac
}

for tenant in a b; do
  [[ -s "$work_root/tenant-$tenant/outputs.json" ]] || {
    echo "tenant $tenant outputs are missing" >&2
    exit 1
  }
done

umask 077
trap 'rm -f "$password_file"' EXIT
aws --profile "$profile" --region "$region" ecr get-login-password >"$password_file"
docker login --username AWS --password-stdin "$registry" <"$password_file" >/dev/null

for component in "${components[@]}"; do
  local_image="vigil-qualification/$component:$tag"
  docker build --platform linux/arm64 \
    --file "$repo_dir/$(dockerfile_for "$component")" \
    --build-arg "VIGIL_VERSION=$tag" \
    --tag "$local_image" "$repo_dir"
  architecture="$(docker image inspect "$local_image" --format '{{.Architecture}}')"
  [[ "$architecture" == "arm64" ]] || {
    echo "$component built for $architecture instead of arm64" >&2
    exit 1
  }
  for tenant in a b; do
    repository="$(jq -er --arg component "$component" '.imageRepositories[$component]' "$work_root/tenant-$tenant/outputs.json")"
    remote="$repository:$tag"
    docker tag "$local_image" "$remote"
    docker push "$remote"
  done
done

receipt="$work_root/image-receipt.json"
jq -n --arg tag "$tag" --arg architecture arm64 '{tag:$tag,architecture:$architecture,images:{}}' >"$receipt"
for tenant in a b; do
  for component in "${components[@]}"; do
    repository="$(jq -er --arg component "$component" '.imageRepositories[$component]' "$work_root/tenant-$tenant/outputs.json")"
    repository_name="${repository#*/}"
    digest="$(aws --profile "$profile" --region "$region" ecr describe-images \
      --repository-name "$repository_name" --image-ids "imageTag=$tag" \
      --query 'imageDetails[0].imageDigest' --output text)"
    jq --arg tenant "$tenant" --arg component "$component" --arg repository "$repository" --arg digest "$digest" \
      '.images[$tenant][$component]={repository:$repository,digest:$digest}' "$receipt" >"$receipt.next"
    mv "$receipt.next" "$receipt"
  done
done
chmod 600 "$receipt"
echo "published $tag for linux/arm64; receipt: $receipt"
