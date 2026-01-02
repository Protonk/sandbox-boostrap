#!/bin/sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/../out/iosurface_trace"
OUT_PATH="${OUT_DIR}/iosurface_trace"

mkdir -p "${OUT_DIR}"

clang -o "${OUT_PATH}" \
  "${SCRIPT_DIR}/iosurface_trace.c" \
  -framework IOKit \
  -framework IOSurface \
  -framework CoreFoundation

echo "[+] built ${OUT_PATH}"
