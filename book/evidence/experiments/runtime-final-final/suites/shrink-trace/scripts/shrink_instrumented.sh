#!/usr/bin/env bash
set -euo pipefail

# Instrumented shrinker: only removes a rule if both fresh and repeat runs succeed.

COMMAND="${1:-}"
SANDBOX_PROFILE="${2:-}"

if [[ -z "${COMMAND}" || -z "${SANDBOX_PROFILE}" ]]; then
  echo "Usage: shrink_instrumented.sh <executable name> <sandbox profile>"
  exit 2
fi

TEMP_SANDBOX_PROFILE="$(mktemp)"
WORK_DIR="${WORK_DIR:-$(pwd)}"
SHRINK_DIR="${SHRINK_DIR:-${WORK_DIR}/phases/shrink}"
SHRINK_METRICS="${SHRINK_DIR}/metrics.jsonl"
SHRUNK_PROFILE="${SHRUNK_PROFILE:-${SANDBOX_PROFILE}.shrunk}"
DYLD_LOG_PATH="${DYLD_LOG_PATH:-${WORK_DIR}/dyld.log}"
PARAM_ARGS=(-D "WORK_DIR=${WORK_DIR}" -D "DYLD_LOG_PATH=${DYLD_LOG_PATH}")

mkdir -p "${SHRINK_DIR}"
: > "${SHRINK_METRICS}"

reset_workspace() {
  rm -rf ./out
}

run_under() {
  local profile="$1"
  set +e
  sandbox-exec "${PARAM_ARGS[@]}" -f "${profile}" ${COMMAND}
  local rc=$?
  set -e
  return "${rc}"
}

write_metric() {
  METRIC_EVENT="$1" \
    METRIC_LINE="$2" \
    METRIC_DECISION="$3" \
    METRIC_RULE="$4" \
    METRIC_FRESH_RC="$5" \
    METRIC_REPEAT_RC="$6" \
    METRIC_PROFILE_LINES="$7" \
    python3 - <<'PY' >> "${SHRINK_METRICS}"
import json
import os

data = {"event": os.environ.get("METRIC_EVENT", "unknown")}
line_val = os.environ.get("METRIC_LINE", "")
if line_val:
    try:
        data["line_number"] = int(line_val)
    except ValueError:
        data["line_number"] = line_val
decision = os.environ.get("METRIC_DECISION")
if decision:
    data["decision"] = decision
rule = os.environ.get("METRIC_RULE")
if rule:
    data["rule"] = rule
fresh_rc = os.environ.get("METRIC_FRESH_RC", "")
if fresh_rc:
    try:
        data["fresh_rc"] = int(fresh_rc)
    except ValueError:
        data["fresh_rc"] = fresh_rc
repeat_rc = os.environ.get("METRIC_REPEAT_RC", "")
if repeat_rc:
    try:
        data["repeat_rc"] = int(repeat_rc)
    except ValueError:
        data["repeat_rc"] = repeat_rc
lines = os.environ.get("METRIC_PROFILE_LINES", "")
if lines:
    try:
        data["profile_lines"] = int(lines)
    except ValueError:
        data["profile_lines"] = lines
print(json.dumps(data))
PY
}

fresh_rc=0
repeat_rc=0

two_phase_check() {
  local profile="$1"
  reset_workspace
  echo "[-] Executing (fresh) ..."
  if run_under "${profile}"; then
    fresh_rc=0
  else
    fresh_rc=$?
    return 1
  fi
  echo "[-] Executing (repeat) ..."
  if run_under "${profile}"; then
    repeat_rc=0
  else
    repeat_rc=$?
    return 1
  fi
  return 0
}

if ! two_phase_check "${SANDBOX_PROFILE}"; then
  line_count="$(wc -l < "${SANDBOX_PROFILE}")"
  write_metric "precheck" "" "failed" "" "${fresh_rc}" "${repeat_rc}" "${line_count}"
  echo "[+] The command could not execute successfully with the initial sandbox profile provided."
  exit 1
else
  line_count="$(wc -l < "${SANDBOX_PROFILE}")"
  write_metric "precheck" "" "ok" "" "${fresh_rc}" "${repeat_rc}" "${line_count}"
  echo "[*] Successful execution of the command with initial sandbox (fresh + repeat)."
fi

LINE_COUNT=$(wc -l < "${SANDBOX_PROFILE}")
cp "${SANDBOX_PROFILE}" "${TEMP_SANDBOX_PROFILE}"

for (( i=LINE_COUNT; i>0; i-- ))
do
  TMP="$(mktemp)"
  sed "${i}d" "${TEMP_SANDBOX_PROFILE}" > "${TMP}"
  LINE="$(sed "${i}q;d" "${SANDBOX_PROFILE}")"

  echo "[-] Attempting to remove line $i: $LINE"
  if two_phase_check "${TMP}"; then
    if echo "${LINE}" | grep -q "([ ]*deny "; then
      echo "[*] Not removing a deny rule"
      write_metric "candidate" "${i}" "kept_deny" "${LINE}" "${fresh_rc}" "${repeat_rc}" "${LINE_COUNT}"
    else
      echo "[+] Removed line $i: unnecessary rule."
      cp "${TMP}" "${TEMP_SANDBOX_PROFILE}"
      write_metric "candidate" "${i}" "removed" "${LINE}" "${fresh_rc}" "${repeat_rc}" "${LINE_COUNT}"
    fi
  else
    echo "[*] Kept line $i: necessary rule."
    write_metric "candidate" "${i}" "kept_required" "${LINE}" "${fresh_rc}" "${repeat_rc}" "${LINE_COUNT}"
  fi
  rm -f "${TMP}"
done

echo "[-] Minimised sandbox profile:"
cat "${TEMP_SANDBOX_PROFILE}"
mkdir -p "$(dirname "${SHRUNK_PROFILE}")"
mv "${TEMP_SANDBOX_PROFILE}" "${SHRUNK_PROFILE}"
