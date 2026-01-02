#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/out}"
BIN_DIR="${BIN_DIR:-${OUT_DIR}/artifacts/bin}"
mkdir -p "${BIN_DIR}"

clang -O2 -Wall -Wextra \
  -o "${BIN_DIR}/sandbox_target" \
  "${ROOT_DIR}/fixtures/sandbox_target.c"

clang -O2 -Wall -Wextra \
  -o "${BIN_DIR}/sandbox_net_required" \
  "${ROOT_DIR}/fixtures/sandbox_net_required.c"

clang -O2 -Wall -Wextra \
  -o "${BIN_DIR}/sandbox_spawn" \
  "${ROOT_DIR}/fixtures/sandbox_spawn.c"

clang -O2 -Wall -Wextra \
  -o "${BIN_DIR}/sandbox_min" \
  "${ROOT_DIR}/fixtures/sandbox_min.c"

echo "[+] Built: ${BIN_DIR}/sandbox_target"
echo "[+] Built: ${BIN_DIR}/sandbox_net_required"
echo "[+] Built: ${BIN_DIR}/sandbox_spawn"
echo "[+] Built: ${BIN_DIR}/sandbox_min"
