#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TF_DIR="${ROOT_DIR}/infra/aws/terraform"

REGION="${AWS_REGION:-us-east-1}"
APP_NAME="${JUDIKT_TF_APP_NAME:-judikt-tf}"
REPOSITORY="${JUDIKT_TF_ECR_REPOSITORY:-judikt}"
TAG="${JUDIKT_IMAGE_TAG:-latest}"
INSTANCE_TYPE="${JUDIKT_INSTANCE_TYPE:-t3.micro}"
AMI_SSM_PARAMETER="${JUDIKT_AMI_SSM_PARAMETER:-/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64}"
ALLOWED_CIDR="${JUDIKT_ALLOWED_CIDR:-127.0.0.1/32}"
PLATFORM="${JUDIKT_DOCKER_PLATFORM:-linux/amd64}"
CONTAINER_MODE="${JUDIKT_MODE:-real-mcp}"
HTTP_BEARER_TOKEN="${JUDIKT_HTTP_BEARER_TOKEN:-}"
APPROVAL_SECRET="${JUDIKT_APPROVAL_SECRET:-}"
AUDIT_HMAC_SECRET="${JUDIKT_AUDIT_HMAC_SECRET:-}"

if [[ -z "${HTTP_BEARER_TOKEN}" || -z "${APPROVAL_SECRET}" || -z "${AUDIT_HMAC_SECRET}" ]]; then
  echo "JUDIKT_HTTP_BEARER_TOKEN, JUDIKT_APPROVAL_SECRET, and JUDIKT_AUDIT_HMAC_SECRET are required" >&2
  exit 2
fi

if [[ "${AUDIT_HMAC_SECRET}" == "${APPROVAL_SECRET}" ]]; then
  echo "JUDIKT_AUDIT_HMAC_SECRET must be independent from JUDIKT_APPROVAL_SECRET" >&2
  exit 2
fi

"${ROOT_DIR}/scripts/aws/preflight_identity.sh" >/dev/null

terraform -chdir="${TF_DIR}" init

terraform -chdir="${TF_DIR}" apply -auto-approve \
  -target=aws_ecr_repository.app \
  -target=aws_secretsmanager_secret.http_bearer_token \
  -target=aws_secretsmanager_secret.approval_secret \
  -target=aws_secretsmanager_secret.audit_hmac_secret \
  -var="aws_region=${REGION}" \
  -var="app_name=${APP_NAME}" \
  -var="repository_name=${REPOSITORY}" \
  -var="image_tag=${TAG}" \
  -var="instance_type=${INSTANCE_TYPE}" \
  -var="ami_ssm_parameter=${AMI_SSM_PARAMETER}" \
  -var="container_mode=${CONTAINER_MODE}" \
  -var="http_bearer_token=${HTTP_BEARER_TOKEN}" \
  -var="approval_secret=${APPROVAL_SECRET}" \
  -var="allowed_cidr=${ALLOWED_CIDR}"

aws secretsmanager put-secret-value \
  --region "${REGION}" \
  --secret-id "${APP_NAME}/http-bearer-token" \
  --secret-string "${HTTP_BEARER_TOKEN}" >/dev/null

aws secretsmanager put-secret-value \
  --region "${REGION}" \
  --secret-id "${APP_NAME}/approval-secret" \
  --secret-string "${APPROVAL_SECRET}" >/dev/null

aws secretsmanager put-secret-value \
  --region "${REGION}" \
  --secret-id "${APP_NAME}/audit-hmac-secret" \
  --secret-string "${AUDIT_HMAC_SECRET}" >/dev/null

IMAGE_URI="$(
  cd "${ROOT_DIR}"
  JUDIKT_ECR_REPOSITORY="${REPOSITORY}" \
  JUDIKT_IMAGE_TAG="${TAG}" \
  JUDIKT_DOCKER_PLATFORM="${PLATFORM}" \
  AWS_REGION="${REGION}" \
    ./scripts/aws/build_push_ecr.sh
)"

echo "Pushed image: ${IMAGE_URI}"

terraform -chdir="${TF_DIR}" apply -auto-approve \
  -var="aws_region=${REGION}" \
  -var="app_name=${APP_NAME}" \
  -var="repository_name=${REPOSITORY}" \
  -var="image_tag=${TAG}" \
  -var="instance_type=${INSTANCE_TYPE}" \
  -var="ami_ssm_parameter=${AMI_SSM_PARAMETER}" \
  -var="container_mode=${CONTAINER_MODE}" \
  -var="http_bearer_token=${HTTP_BEARER_TOKEN}" \
  -var="approval_secret=${APPROVAL_SECRET}" \
  -var="allowed_cidr=${ALLOWED_CIDR}"

terraform -chdir="${TF_DIR}" output
