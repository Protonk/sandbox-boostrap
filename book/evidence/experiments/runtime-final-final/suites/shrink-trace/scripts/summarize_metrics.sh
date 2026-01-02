#!/usr/bin/env bash
set -euo pipefail

RUN_DIR="${1:-}"
if [[ -z "${RUN_DIR}" ]]; then
  RUN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/out"
fi
if [[ ! -d "${RUN_DIR}" ]]; then
  echo "Usage: summarize_metrics.sh <run_dir>"
  exit 2
fi

RUN_JSON="${RUN_DIR}/run.json"
if [[ ! -f "${RUN_JSON}" ]]; then
  echo "[!] Missing run.json in ${RUN_DIR}"
  exit 1
fi

RUN_DIR="${RUN_DIR}" python3 - <<'PY'
import json
import os
from pathlib import Path

run_dir = Path(os.environ.get("RUN_DIR", "."))
data = json.loads((run_dir / "run.json").read_text())

trace = data.get("trace", {})
shrink = data.get("shrink", {})

print(f"[*] Summary for: {run_dir}")
print(f"world_id: {data.get('world_id', '')}")
print(f"fixture: {data.get('knobs', {}).get('fixture', '')}")
print(f"trace status: {trace.get('status', 'unknown')}")
print(f"trace iterations: {trace.get('iterations')}")
print(f"trace profile lines: {trace.get('profile_lines')}")
print(f"bad rules: {trace.get('bad_rules')}")
print(f"shrink status: {shrink.get('status', 'unknown')}")
print(f"shrink removed: {shrink.get('removed')}")
print(f"shrink kept: {shrink.get('kept')}")
print(f"post-shrink fresh rc: {shrink.get('post_shrink_fresh_rc')}")
print(f"post-shrink repeat rc: {shrink.get('post_shrink_repeat_rc')}")
PY
