#!/bin/zsh
set -euo pipefail

# Compile a small set of system SBPL profiles into binary blobs using libsandbox.
# This demonstrates the SBPL -> compiled graph step from Orientation.md §3.2 on
# macOS 14.x, replacing the old kernelcache offset scraper.

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/build/profiles"
PROFILES_DIR="/System/Library/Sandbox/Profiles"
NAMES=("airlock.sb" "bsd.sb")

mkdir -p "$OUT"

echo "[*] compiling profiles from $PROFILES_DIR"
python3 "$ROOT/compile_profiles.py" --profiles-dir "$PROFILES_DIR" --names "${NAMES[@]}" --out-dir "$OUT"

echo
echo "[*] outputs in $OUT (feed these .sb.bin files into sbdis or other decoders)."
