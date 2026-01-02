#!/bin/sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
SCRIPT="$REPO_ROOT/book/experiments/runtime-final-final/suites/nonbaseline/MACF-wrapper/sb/scan_xattr_hooks.d"
OUT_DIR="$REPO_ROOT/book/experiments/runtime-final-final/suites/nonbaseline/MACF-wrapper/out/raw"
LOG_PATH="$OUT_DIR/xattr_scan.log"
TEST_DIR="$REPO_ROOT/book/experiments/runtime-final-final/suites/nonbaseline/MACF-wrapper/out/tmp"
TEST_FILE="$TEST_DIR/macf_wrapper_xattr_test"

mkdir -p "$OUT_DIR"
mkdir -p "$TEST_DIR"
/usr/bin/touch "$TEST_FILE"

CMD="/usr/bin/xattr -w com.airlock.macfwrapper hello $TEST_FILE"

echo "Running xattr scan: $CMD"
sudo -n /usr/sbin/dtrace -q -s "$SCRIPT" -c "$CMD" >"$LOG_PATH"
if [ ! -s "$LOG_PATH" ]; then
  echo "# no mac_*xattr* events observed for command: $CMD" >"$LOG_PATH"
fi
echo "Wrote scan log to $LOG_PATH"
