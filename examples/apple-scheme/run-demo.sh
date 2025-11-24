#!/bin/zsh
set -euo pipefail

# Build the compiler shim and compile the demo SBPL profile into a binary blob.
# This exercises the TinyScheme → compiled policy step from Orientation.md §3.2
# using the modern libsandbox entry points.

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$ROOT/build"
BIN="$BUILD_DIR/compile_profile"
IN="$ROOT/profiles/demo.sb"
OUT="$BUILD_DIR/demo.sb.bin"

if [[ ! -x "$BIN" ]]; then
  echo "[*] building compiler demo..."
  make -C "$ROOT"
fi

echo "[*] compiling $IN -> $OUT"
"$BIN" "$IN" "$OUT"

echo
echo "[*] bytecode saved to $OUT (use sbdis or other decoders to inspect the graph)."
