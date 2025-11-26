#!/bin/zsh
set -euo pipefail

# Build and run the sandbox call demo. Shows how to invoke libsandbox’s private
# compile/apply interfaces on macOS 14.x and what happens when apply is blocked.

ROOT="$(cd "$(dirname "$0")" && pwd)"
BIN="$ROOT/build/sandbox_calls_demo"

if [[ ! -x "$BIN" ]]; then
  make -C "$ROOT"
fi

echo "[*] running sandbox_calls_demo"
"$BIN"
