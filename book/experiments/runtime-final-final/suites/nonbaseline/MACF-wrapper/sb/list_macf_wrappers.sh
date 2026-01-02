#!/bin/sh
set -euo pipefail

# Enumerate fbt entry probes for MACF wrapper functions (mac_*) and write them
# to out/meta/macf_wrapper_probes.txt for this runtime VM.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$BASE_DIR/out/meta"
OUT_PATH="$OUT_DIR/macf_wrapper_probes.txt"

mkdir -p "$OUT_DIR"

# This relies on SIP being disabled so that the fbt provider is usable.
# Use sudo externally if needed.
dtrace -ln 'fbt:mach_kernel:mac_*:entry' | sort >"$OUT_PATH"

echo "Wrote MACF wrapper probe list to $OUT_PATH"
