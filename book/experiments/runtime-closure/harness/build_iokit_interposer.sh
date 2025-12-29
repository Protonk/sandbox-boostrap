#!/bin/sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/../out/interposer"
OUT_PATH="${OUT_DIR}/iokit_call_interpose.dylib"

mkdir -p "${OUT_DIR}"

clang -dynamiclib \
  -o "${OUT_PATH}" \
  "${SCRIPT_DIR}/iokit_call_interpose.c" \
  -framework IOKit \
  -framework CoreFoundation

echo "[+] built ${OUT_PATH}"
