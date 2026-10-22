#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build/serverless"
ZIP_PATH="${ROOT_DIR}/build/judikt-serverless.zip"

if ! command -v zip >/dev/null 2>&1; then
  echo "zip is required to package the serverless Lambda artifact" >&2
  exit 1
fi

mkdir -p "${BUILD_DIR}" "${ROOT_DIR}/build"
find "${BUILD_DIR}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +

cp -R "${ROOT_DIR}/src/judikt" "${BUILD_DIR}/judikt"
find "${BUILD_DIR}" -type d -name "__pycache__" -prune -exec rm -rf {} +
find "${BUILD_DIR}" -type f -name "*.pyc" -delete

(
  cd "${BUILD_DIR}"
  zip -qr "${ZIP_PATH}" .
)

echo "${ZIP_PATH}"
