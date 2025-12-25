#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/out"
mkdir -p "${OUT_DIR}"

clang -O2 -Wall -Wextra \
  -o "${OUT_DIR}/sandbox_target" \
  "${ROOT_DIR}/fixtures/sandbox_target.c"

clang -O2 -Wall -Wextra \
  -o "${OUT_DIR}/sandbox_min" \
  "${ROOT_DIR}/fixtures/sandbox_min.c"

echo "[+] Built: ${OUT_DIR}/sandbox_target"
echo "[+] Built: ${OUT_DIR}/sandbox_min"
