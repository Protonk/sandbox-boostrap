#!/bin/zsh
set -euo pipefail

# Compile the sample SBPL into a binary policy blob for decoding demos.

ROOT="$(cd "$(dirname "$0")" && pwd)"

python3 "$ROOT/compile_sample.py"

echo
echo "[*] Output: $ROOT/build/sample.sb.bin"
echo "    Feed this into sbdis/resnarf/re2dot to explore headers, filters, and regexes."
