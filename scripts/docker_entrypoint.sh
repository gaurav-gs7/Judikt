#!/usr/bin/env bash
set -euo pipefail
MODE="${JUDIKT_MODE:-real-mcp}"

case "${MODE}" in
  dashboard)
    exec python -m judikt.cli dashboard --host 0.0.0.0 --port "${PORT:-8080}"
    ;;
  real-mcp)
    exec python -m judikt.cli serve-real-mcp --host 0.0.0.0 --port "${PORT:-8080}"
    ;;
  *)
    echo "unsupported JUDIKT_MODE=${MODE}; expected dashboard or real-mcp" >&2
    exit 2
    ;;
esac
