#!/usr/bin/env bash
set -euo pipefail
REGION="${AWS_REGION:-us-east-1}"
STACK_NAME="${JUDIKT_STACK_NAME:-judikt-free-tier}"

./scripts/aws/preflight_identity.sh >/dev/null

aws cloudformation delete-stack --region "${REGION}" --stack-name "${STACK_NAME}"
echo "Delete requested for stack ${STACK_NAME} in ${REGION}."
echo "Watch cleanup with: aws cloudformation wait stack-delete-complete --region ${REGION} --stack-name ${STACK_NAME}"
