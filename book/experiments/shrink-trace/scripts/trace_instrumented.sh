#!/usr/bin/env bash
set -euo pipefail

PROGRAM_NAME="${1:-}"
SANDBOX_PROFILE="${2:-}"

if [[ -z "${PROGRAM_NAME}" || -z "${SANDBOX_PROFILE}" ]]; then
  echo "Usage: trace_instrumented.sh <executable-name> <sandbox-profile>"
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${ROOT_DIR}/../../.." && pwd)"
PREFLIGHT_TOOL="${REPO_ROOT}/book/tools/preflight/preflight.py"

if [[ "${SANDBOX_PROFILE}" == "${REPO_ROOT}/"* ]]; then
  SANDBOX_PROFILE_REL="${SANDBOX_PROFILE#${REPO_ROOT}/}"
else
  SANDBOX_PROFILE_REL="${SANDBOX_PROFILE}"
fi

# Prefer a predicate known to surface sandbox violations in unified logs.
# Chromium docs: include com.apple.sandbox.reporting in addition to /Sandbox sender image. :contentReference[oaicite:12]{index=12}
LOG_PREDICATE='((processID == 0) AND (senderImagePath CONTAINS "/Sandbox")) OR (subsystem == "com.apple.sandbox.reporting") OR (sender == "Sandbox")'

WORK_DIR="${WORK_DIR:-$(pwd)}"
LOG_DIR="${WORK_DIR}/logs"
METRICS_TSV="${WORK_DIR}/metrics.tsv"
MAX_ITERS="${MAX_ITERS:-50}"
SUCCESS_CODE="${SUCCESS_CODE:-0}"
LOG_FLUSH_SECONDS="${LOG_FLUSH_SECONDS:-5}"
SEED_DYLD="${SEED_DYLD:-1}"
TRACE_STATUS="${WORK_DIR}/trace_status.txt"
LOG_SHOW_WINDOW="${LOG_SHOW_WINDOW:-2m}"
DENY_EXTRACTOR="${ROOT_DIR}/scripts/extract_denies.py"

mkdir -p "${LOG_DIR}"
: > "${TRACE_STATUS}"

# Initialize profile if missing (same shape as upstream, with optional dyld seed). :contentReference[oaicite:13]{index=13}
if [[ ! -f "${SANDBOX_PROFILE}" ]]; then
  if [[ "${SEED_DYLD}" -eq 1 ]]; then
    cat > "${SANDBOX_PROFILE}" <<'EOF'
(version 1)
(debug deny)
(deny default)
(allow file-read*
  (subpath "/System/Library/Frameworks")
  (subpath "/System/Library/PrivateFrameworks")
  (subpath "/usr/lib")
)
(allow file-read* file-map-executable
  (subpath "/System/Cryptexes/App")
  (subpath "/System/Cryptexes/OS")
  (subpath "/System/Volumes/Preboot/Cryptexes/App/System")
  (subpath "/System/Volumes/Preboot/Cryptexes/OS")
)
(allow file-read-metadata (subpath "/"))
EOF
  else
    cat > "${SANDBOX_PROFILE}" <<'EOF'
(version 1)
(deny default)
EOF
  fi
fi

echo -e "iter\treturn_code\tdenies_seen\tnew_rules\tprofile_lines" > "${METRICS_TSV}"

iter=0
while true; do
  iter=$((iter + 1))
  if (( iter > MAX_ITERS )); then
    echo "[!] Reached MAX_ITERS=${MAX_ITERS}; stopping."
    break
  fi

  iter_preflight="${LOG_DIR}/iter_${iter}_preflight.json"
  if (cd "${REPO_ROOT}" && python3 "${PREFLIGHT_TOOL}" scan "${SANDBOX_PROFILE_REL}" > "${iter_preflight}"); then
    :
  else
    preflight_rc=$?
    echo "[!] Preflight scan failed (rc=${preflight_rc}); stopping. See ${iter_preflight}"
    echo "status=preflight_failed" > "${TRACE_STATUS}"
    echo "iter=${iter}" >> "${TRACE_STATUS}"
    echo "preflight_rc=${preflight_rc}" >> "${TRACE_STATUS}"
    echo "preflight_json=${iter_preflight}" >> "${TRACE_STATUS}"
    break
  fi

  iter_log="${LOG_DIR}/iter_${iter}.log"
  iter_stdout="${LOG_DIR}/iter_${iter}_stdout.txt"
  iter_stderr="${LOG_DIR}/iter_${iter}_stderr.txt"
  : > "${iter_log}"
  : > "${iter_stdout}"
  : > "${iter_stderr}"

  before_lines="$(wc -l < "${SANDBOX_PROFILE}" | tr -d ' ')"

  echo "[-] Iteration ${iter}: starting log stream"
  log stream --style json --info --debug --predicate "${LOG_PREDICATE}" > "${iter_log}" &
  LOG_PID=$!
  sleep 1

  echo "[-] Iteration ${iter}: executing under sandbox-exec"
  # NOTE: This matches the upstream constraint: PROGRAM_NAME is treated as the executable, no args.
  sandbox-exec -f "${SANDBOX_PROFILE}" "${PROGRAM_NAME}" > "${iter_stdout}" 2> "${iter_stderr}" &
  PROGRAM_PID=$!
  echo "${PROGRAM_PID}" > "${LOG_DIR}/iter_${iter}_pid.txt"

  if wait "${PROGRAM_PID}"; then
    RETURN_CODE=0
  else
    RETURN_CODE=$?
  fi

  # Give the logger a moment to flush, then stop it.
  sleep "${LOG_FLUSH_SECONDS}"
  kill "${LOG_PID}" 2>/dev/null || true
  wait "${LOG_PID}" 2>/dev/null || true
  prev_size=0
  for _ in 1 2 3 4 5; do
    cur_size=$(wc -c < "${iter_log}" | tr -d ' ')
    if [[ "${cur_size}" -eq "${prev_size}" ]]; then
      break
    fi
    prev_size="${cur_size}"
    sleep 0.5
  done

  # Extract deny lines associated with this PID from JSON eventMessage fields.
  deny_lines_tmp="$(mktemp)"
  python3 "${DENY_EXTRACTOR}" "${iter_log}" "${PROGRAM_PID}" > "${deny_lines_tmp}"
  denies_seen="$(wc -l < "${deny_lines_tmp}" | tr -d ' ')"
  if [[ "${denies_seen}" -eq 0 ]]; then
    iter_log_show="${LOG_DIR}/iter_${iter}_log_show.json"
    sleep 1
    /usr/bin/log show --last "${LOG_SHOW_WINDOW}" --style json --predicate "${LOG_PREDICATE}" > "${iter_log_show}" 2>/dev/null || true
    python3 "${DENY_EXTRACTOR}" "${iter_log_show}" "${PROGRAM_PID}" > "${deny_lines_tmp}"
    denies_seen="$(wc -l < "${deny_lines_tmp}" | tr -d ' ')"
  fi

  new_rules=0
  while IFS= read -r line; do
    rule="$(echo "${line}" \
      | sed "s/.* deny([0-9]*) \([^ ]*\) \([^ ]*\).*$/\(allow \1 (literal \"\2\"))/" \
      | sed "s/sysctl-\(.*\) (literal /sysctl-\1 (sysctl-name /" \
      | sed "s/\"path:/\"/" \
      | sed "s/network-\(.*\) (literal /network-\1 (local ip /" \
      | sed "s/\"local:\*/\"localhost/" \
      | sed "s/.* deny([0-9]*) \([^ ]*\)/\(allow \1)/" \
      | sed "s/mach-lookup (literal /mach-lookup (global-name /" \
      | sed "s/network-\([^ ]*\) (local ip \"\/.*\"/network-\1 (local ip \"localhost:2000\"/" \
    )"

    # Only append if the exact line is not already present.
    if ! grep -Fqx "${rule}" "${SANDBOX_PROFILE}"; then
      echo "${rule}" >> "${SANDBOX_PROFILE}"
      new_rules=$((new_rules + 1))
    fi
  done < "${deny_lines_tmp}"
  rm -f "${deny_lines_tmp}"

  after_lines="$(wc -l < "${SANDBOX_PROFILE}" | tr -d ' ')"
  echo -e "${iter}\t${RETURN_CODE}\t${denies_seen}\t${new_rules}\t${after_lines}" >> "${METRICS_TSV}"

  echo "[-] Iteration ${iter} done: rc=${RETURN_CODE}, denies=${denies_seen}, new_rules=${new_rules}, lines=${after_lines}"

  # Stop conditions: success, continue if rules added, otherwise record a stall/no-new-rules reason.
  if [[ "${RETURN_CODE}" -eq "${SUCCESS_CODE}" ]]; then
    echo "[+] Return code ${RETURN_CODE} == SUCCESS_CODE ${SUCCESS_CODE}; stopping."
    echo "status=success" > "${TRACE_STATUS}"
    echo "iter=${iter}" >> "${TRACE_STATUS}"
    break
  fi
  if [[ "${new_rules}" -gt 0 ]]; then
    continue
  fi

  if [[ "${RETURN_CODE}" -ge 128 ]]; then
    stall_dir="${WORK_DIR}/stall_iter_${iter}"
    mkdir -p "${stall_dir}"
    cp "${SANDBOX_PROFILE}" "${stall_dir}/profile.sb"
    cp "${iter_log}" "${stall_dir}/iter_${iter}.log"
    cp "${iter_preflight}" "${stall_dir}/iter_${iter}_preflight.json"
    cp "${iter_stdout}" "${stall_dir}/iter_${iter}_stdout.txt"
    cp "${iter_stderr}" "${stall_dir}/iter_${iter}_stderr.txt"
    echo "rc=${RETURN_CODE}" > "${stall_dir}/reason.txt"
    echo "new_rules=${new_rules}" >> "${stall_dir}/reason.txt"
    echo "denies_seen=${denies_seen}" >> "${stall_dir}/reason.txt"

    /usr/bin/log show --last 2m --style json --predicate "${LOG_PREDICATE}" > "${stall_dir}/log_show.json" 2>/dev/null || true

    for crash_dir in "${HOME}/Library/Logs/DiagnosticReports" "/Library/Logs/DiagnosticReports"; do
      if [[ -d "${crash_dir}" ]]; then
        crash_file="$(ls -t "${crash_dir}"/sandbox_target_*.crash "${crash_dir}"/sandbox-exec_*.crash 2>/dev/null | head -n 1 || true)"
        if [[ -n "${crash_file}" ]]; then
          cp "${crash_file}" "${stall_dir}/"
          break
        fi
      fi
    done

    echo "[!] Stalled on signal with no new rules; bundle: ${stall_dir}"
    echo "status=stalled" > "${TRACE_STATUS}"
    echo "iter=${iter}" >> "${TRACE_STATUS}"
    echo "stall_dir=${stall_dir}" >> "${TRACE_STATUS}"
    break
  fi

  echo "[*] No new rules added; stopping."
  echo "status=no_new_rules" > "${TRACE_STATUS}"
  echo "iter=${iter}" >> "${TRACE_STATUS}"
  break
done

echo "Updated sandbox profile: ${SANDBOX_PROFILE}"
