#!/usr/bin/env bash
set -euo pipefail
REGION="${AWS_REGION:-us-east-1}"
REPOSITORY="${JUDIKT_ECR_REPOSITORY:-judikt}"
TAG="${JUDIKT_IMAGE_TAG:-latest}"
PLATFORM="${JUDIKT_DOCKER_PLATFORM:-linux/amd64}"

./scripts/aws/preflight_identity.sh >/dev/null
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
IMAGE_URI="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${REPOSITORY}:${TAG}"

aws ecr describe-repositories \
  --region "${REGION}" \
  --repository-names "${REPOSITORY}" >/dev/null 2>&1 \
  || aws ecr create-repository \
    --region "${REGION}" \
    --repository-name "${REPOSITORY}" \
    --image-scanning-configuration scanOnPush=true \
    --encryption-configuration encryptionType=AES256 >/dev/null

aws ecr get-login-password --region "${REGION}" \
  | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

docker buildx build --platform "${PLATFORM}" -t "${IMAGE_URI}" --push .

echo "${IMAGE_URI}"
