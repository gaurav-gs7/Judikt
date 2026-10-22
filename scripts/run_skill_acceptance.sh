#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -n "${PYTHON:-}" ]]; then
  PYTHON_BIN="${PYTHON}"
elif [[ -x .venv/bin/python ]]; then
  PYTHON_BIN=.venv/bin/python
else
  PYTHON_BIN=python3
fi
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/judikt-skill-acceptance.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT

mkdir -p "${WORK_DIR}/dist" "${WORK_DIR}/home"
"${PYTHON_BIN}" -m pip wheel \
  --no-deps \
  --wheel-dir "${WORK_DIR}/dist" \
  . >/dev/null
"${PYTHON_BIN}" -m venv "${WORK_DIR}/venv"
"${WORK_DIR}/venv/bin/python" -m pip install \
  --no-deps \
  "${WORK_DIR}"/dist/judikt-*.whl >/dev/null

HOME="${WORK_DIR}/home" \
PATH="${WORK_DIR}/venv/bin:${PATH}" \
JUDIKT_ACCEPTANCE_FRESH_INSTALL=1 \
"${WORK_DIR}/venv/bin/python" tests/test_skill_acceptance.py

echo "Judikt skill acceptance passed against a fresh wheel installation."
