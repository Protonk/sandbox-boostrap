#!/bin/sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
PY_BIN="$REPO_ROOT/.venv/bin/python"
CAPTURE="$REPO_ROOT/book/experiments/runtime-final-final/suites/nonbaseline/MACF-wrapper/capture.py"
PYTHONPATH="$REPO_ROOT"

run_capture() {
  run_id="$1"
  scenario="$2"
  desc="$3"
  cmd="$4"
  raw_out="$REPO_ROOT/book/experiments/runtime-final-final/suites/nonbaseline/MACF-wrapper/out/raw/${run_id}.log"
  json_out="$REPO_ROOT/book/experiments/runtime-final-final/suites/nonbaseline/MACF-wrapper/out/json/${run_id}.json"
  sudo -n env PYTHONPATH="$PYTHONPATH" "$PY_BIN" \
    "$CAPTURE" \
    --run-id "$run_id" \
    --scenario "$scenario" \
    --scenario-description "$desc" \
    --run-command "$cmd" \
    --raw-out "$raw_out" \
    --json-out "$json_out"
  echo "Raw log: $raw_out"
  echo "JSON:    $json_out"
}

run_capture macf_vnode_open_ls "vnode_open_ls_tmp" "run /bin/ls /tmp; expect mac_vnode_check_open" "/bin/ls /tmp"

TEST_DIR="$REPO_ROOT/book/experiments/runtime-final-final/suites/nonbaseline/MACF-wrapper/out/tmp"
mkdir -p "$TEST_DIR"
TEST_FILE="$TEST_DIR/macf_wrapper_xattr_test"
/usr/bin/touch "$TEST_FILE"
run_capture macf_setxattr_test "xattr_tmp_file" "set com.airlock.macfwrapper on out/tmp/macf_wrapper_xattr_test via xattr(1)" "/usr/bin/xattr -w com.airlock.macfwrapper hello $TEST_FILE"
