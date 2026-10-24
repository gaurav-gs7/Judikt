#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# The acceptance run must exercise the built wheel, never the source tree. An
# inherited PYTHONPATH=src (set by this repository's own run_*.sh helpers) makes
# pip treat the checkout's judikt.egg-info as already installed and skip the
# wheel, so clear every variable that can redirect imports or installs.
unset PYTHONPATH PYTHONHOME PYTHONUSERBASE PYTHONSTARTUP PIP_TARGET PIP_PREFIX PIP_USER

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
  --force-reinstall \
  "${WORK_DIR}"/dist/judikt-*.whl >/dev/null
"${WORK_DIR}/venv/bin/python" -I -c '
import importlib.metadata, sys, judikt
version = importlib.metadata.version("judikt")
if not judikt.__file__.startswith(sys.prefix):
    raise SystemExit(f"judikt was imported from {judikt.__file__}, not the fresh wheel in {sys.prefix}")
print(f"Testing installed wheel judikt {version} from {sys.prefix}")
'

HOME="${WORK_DIR}/home" \
PATH="${WORK_DIR}/venv/bin:${PATH}" \
JUDIKT_ACCEPTANCE_FRESH_INSTALL=1 \
"${WORK_DIR}/venv/bin/python" tests/test_skill_acceptance.py

echo "Judikt skill acceptance passed against a fresh wheel installation."
