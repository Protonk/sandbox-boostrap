#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${ROOT_DIR}/../../.." && pwd)"
TOOL="${REPO_ROOT}/book/tools/sbpl/trace_shrink/trace_shrink.py"

exec python3 "${TOOL}" workflow "$@"
