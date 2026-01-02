#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/../out/interposer"
mkdir -p "${OUT_DIR}"
OUT_PATH="${OUT_DIR}/sbpl_trace_interpose.dylib"
TMP_PATH="${OUT_PATH}.tmp"

clang -dynamiclib \
  -Wl,-undefined,dynamic_lookup \
  -o "${TMP_PATH}" \
  "${SCRIPT_DIR}/sbpl_trace_interpose.c" \
  "${SCRIPT_DIR}/mach_exc_server.c" \
  "${SCRIPT_DIR}/mach_exc_user.c"

mv -f "${TMP_PATH}" "${OUT_PATH}"
echo "[+] wrote ${OUT_PATH}"
