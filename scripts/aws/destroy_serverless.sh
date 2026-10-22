#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TF_DIR="${ROOT_DIR}/infra/aws/serverless"

REGION="${AWS_REGION:-us-east-1}"
APP_NAME="${JUDIKT_SERVERLESS_APP_NAME:-judikt-serverless}"
ZIP_PATH="${ROOT_DIR}/build/judikt-serverless.zip"

"${ROOT_DIR}/scripts/aws/preflight_identity.sh" >/dev/null

if [[ ! -f "${ZIP_PATH}" ]]; then
  "${ROOT_DIR}/scripts/aws/package_serverless.sh" >/dev/null
fi

terraform -chdir="${TF_DIR}" destroy -auto-approve \
  -var="aws_region=${REGION}" \
  -var="app_name=${APP_NAME}" \
  -var="lambda_zip_path=${ZIP_PATH}"
