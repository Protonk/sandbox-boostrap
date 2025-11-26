#!/bin/zsh
set -euo pipefail

# Disassemble an early-format sandbox profile using the legacy decision-tree parser.
# Usage: ./run-demo.sh path/to/legacy.sb.bin

if [[ $# -ne 1 ]]; then
  echo "usage: $0 path/to/legacy.sb.bin"
  echo "Note: sbdis currently supports only the early decision-tree format."
  exit 1
fi

ROOT="$(cd "$(dirname "$0")" && pwd)"
PROFILE_BIN="$1"

python3 "$ROOT/sbdis.py" osx "$PROFILE_BIN"
