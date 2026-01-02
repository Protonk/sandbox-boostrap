#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${ROOT_DIR}/../../.." && pwd)"
OUT_ROOT="${ROOT_DIR}/out"
MATRIX_DIR="${OUT_ROOT}/matrix"
SUMMARY_JSON="${MATRIX_DIR}/summary.json"

mkdir -p "${MATRIX_DIR}"

fixtures=("sandbox_target" "sandbox_net_required" "sandbox_spawn")
import_vals=(1 0)
network_rules=("parsed" "drop")
streaks=(2 3)

for fixture in "${fixtures[@]}"; do
  for import_dyld in "${import_vals[@]}"; do
    for net_rule in "${network_rules[@]}"; do
      for streak in "${streaks[@]}"; do
        label="${fixture}_dyld${import_dyld}_net${net_rule}_streak${streak}"
        run_dir="${MATRIX_DIR}/${label}"
        mkdir -p "${run_dir}"
        set +e
        OUT_DIR="${run_dir}" \
          FIXTURE_BIN="${fixture}" \
          IMPORT_DYLD_SUPPORT="${import_dyld}" \
          NETWORK_RULES="${net_rule}" \
          SUCCESS_STREAK="${streak}" \
          "${ROOT_DIR}/scripts/run_workflow.sh" > "${run_dir}/run.log" 2>&1
        set -e
      done
    done
  done
done

PYTHONPATH="${REPO_ROOT}" MATRIX_DIR="${MATRIX_DIR}" SUMMARY_JSON="${SUMMARY_JSON}" python3 - <<'PY'
import json
import os
from pathlib import Path
from book.api import path_utils

matrix_dir = Path(os.environ["MATRIX_DIR"])
summary_path = Path(os.environ["SUMMARY_JSON"])
runs = []
world_id = ""

for run_json in sorted(matrix_dir.glob("*/run.json")):
    data = json.loads(run_json.read_text())
    if not world_id:
        world_id = data.get("world_id", "")
    runs.append(
        {
            "label": run_json.parent.name,
            "run_dir": path_utils.to_repo_relative(run_json.parent),
            "fixture": data.get("knobs", {}).get("fixture"),
            "import_dyld_support": data.get("knobs", {}).get("import_dyld_support"),
            "network_rules": data.get("knobs", {}).get("network_rules"),
            "success_streak": data.get("knobs", {}).get("success_streak"),
            "trace_status": data.get("trace", {}).get("status"),
            "trace_iterations": data.get("trace", {}).get("iterations"),
            "trace_lines": data.get("trace", {}).get("profile_lines"),
            "shrunk_lines": data.get("shrink", {}).get("profile_lines"),
            "bad_rules": data.get("trace", {}).get("bad_rules"),
            "shrink_removed": data.get("shrink", {}).get("removed"),
            "shrink_kept": data.get("shrink", {}).get("kept"),
            "post_shrink_fresh_rc": data.get("shrink", {}).get("post_shrink_fresh_rc"),
            "post_shrink_repeat_rc": data.get("shrink", {}).get("post_shrink_repeat_rc"),
        }
    )

summary = {
    "world_id": world_id,
    "matrix_dir": path_utils.to_repo_relative(matrix_dir),
    "runs": runs,
}
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True))
PY

echo "[+] Wrote summary: ${SUMMARY_JSON}"
