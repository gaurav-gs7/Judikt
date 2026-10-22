#!/usr/bin/env bash
set -euo pipefail
REGION="${AWS_REGION:-us-east-1}"
STACK_NAME="${JUDIKT_STACK_NAME:-judikt-free-tier}"
INSTANCE_TYPE="${JUDIKT_INSTANCE_TYPE:-t3.micro}"
ALLOWED_CIDR="${JUDIKT_ALLOWED_CIDR:-127.0.0.1/32}"
TEMPLATE="${JUDIKT_TEMPLATE:-infra/aws/cloudformation/judikt-ec2.yml}"
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

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <ecr-image-uri>" >&2
  echo "example: $0 123456789012.dkr.ecr.us-east-1.amazonaws.com/judikt:latest" >&2
  exit 2
fi

IMAGE_URI="$1"

./scripts/aws/preflight_identity.sh >/dev/null

aws cloudformation deploy \
  --region "${REGION}" \
  --stack-name "${STACK_NAME}" \
  --template-file "${TEMPLATE}" \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    ImageUri="${IMAGE_URI}" \
    InstanceType="${INSTANCE_TYPE}" \
    AllowedCidr="${ALLOWED_CIDR}" \
    ContainerMode="${CONTAINER_MODE}" \
    HttpBearerToken="${HTTP_BEARER_TOKEN}" \
    ApprovalSecret="${APPROVAL_SECRET}" \
    AuditHmacSecret="${AUDIT_HMAC_SECRET}"

aws cloudformation describe-stacks \
  --region "${REGION}" \
  --stack-name "${STACK_NAME}" \
  --query "Stacks[0].Outputs" \
  --output table
