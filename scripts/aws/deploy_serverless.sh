#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TF_DIR="${ROOT_DIR}/infra/aws/serverless"

REGION="${AWS_REGION:-us-east-1}"
APP_NAME="${JUDIKT_SERVERLESS_APP_NAME:-judikt-serverless}"
API_TOKEN="${JUDIKT_API_TOKEN:-}"
APPROVAL_SECRET="${JUDIKT_APPROVAL_SECRET:-}"
AUDIT_HMAC_SECRET="${JUDIKT_AUDIT_HMAC_SECRET:-}"

if [[ -z "${API_TOKEN}" || -z "${APPROVAL_SECRET}" || -z "${AUDIT_HMAC_SECRET}" ]]; then
  echo "JUDIKT_API_TOKEN, JUDIKT_APPROVAL_SECRET, and JUDIKT_AUDIT_HMAC_SECRET are required" >&2
  exit 2
fi

if [[ "${AUDIT_HMAC_SECRET}" == "${APPROVAL_SECRET}" ]]; then
  echo "JUDIKT_AUDIT_HMAC_SECRET must be independent from JUDIKT_APPROVAL_SECRET" >&2
  exit 2
fi

"${ROOT_DIR}/scripts/aws/preflight_identity.sh" >/dev/null
ZIP_PATH="$("${ROOT_DIR}/scripts/aws/package_serverless.sh")"

terraform -chdir="${TF_DIR}" init

terraform -chdir="${TF_DIR}" apply -auto-approve \
  -target=aws_secretsmanager_secret.api_token \
  -target=aws_secretsmanager_secret.approval_secret \
  -target=aws_secretsmanager_secret.audit_hmac_secret \
  -var="aws_region=${REGION}" \
  -var="app_name=${APP_NAME}" \
  -var="lambda_zip_path=${ZIP_PATH}"

aws secretsmanager put-secret-value \
  --region "${REGION}" \
  --secret-id "${APP_NAME}/api-token" \
  --secret-string "${API_TOKEN}" >/dev/null

aws secretsmanager put-secret-value \
  --region "${REGION}" \
  --secret-id "${APP_NAME}/approval-secret" \
  --secret-string "${APPROVAL_SECRET}" >/dev/null

aws secretsmanager put-secret-value \
  --region "${REGION}" \
  --secret-id "${APP_NAME}/audit-hmac-secret" \
  --secret-string "${AUDIT_HMAC_SECRET}" >/dev/null

terraform -chdir="${TF_DIR}" apply -auto-approve \
  -var="aws_region=${REGION}" \
  -var="app_name=${APP_NAME}" \
  -var="lambda_zip_path=${ZIP_PATH}"

terraform -chdir="${TF_DIR}" output
