#!/usr/bin/env bash
set -euo pipefail

CACHE_PATH="/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e"
OUT_DIR="${1:-/tmp/dsc_extract}"

echo "[*] cache: $CACHE_PATH"
echo "[*] out:   $OUT_DIR"

if [[ ! -f "$CACHE_PATH" ]]; then
  echo "cache not found at $CACHE_PATH" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

# Requires dyld-shared-cache-extractor (https://github.com/keith/dyld-shared-cache-extractor)
if ! command -v dyld-shared-cache-extractor >/dev/null 2>&1; then
  echo "dyld-shared-cache-extractor not installed; install from https://github.com/keith/dyld-shared-cache-extractor" >&2
  exit 1
fi

dyld-shared-cache-extractor "$CACHE_PATH" "$OUT_DIR/extracted"
echo "[+] extracted to $OUT_DIR/extracted"
echo "libsystem_sandbox.dylib should be under $OUT_DIR/extracted/usr/lib/system/"
