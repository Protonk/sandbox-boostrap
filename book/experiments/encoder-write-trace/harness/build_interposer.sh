#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/../out/interposer"
mkdir -p "${OUT_DIR}"

clang -dynamiclib \
  -Wl,-undefined,dynamic_lookup \
  -o "${OUT_DIR}/sbpl_trace_interpose.dylib" \
  "${SCRIPT_DIR}/sbpl_trace_interpose.c"

echo "[+] wrote ${OUT_DIR}/sbpl_trace_interpose.dylib"
