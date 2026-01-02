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

# Prefer a predicate known to surface sandbox violations in unified logs.
# Chromium docs: include com.apple.sandbox.reporting in addition to /Sandbox sender image. :contentReference[oaicite:12]{index=12}
LOG_PREDICATE='((processID == 0) AND (senderImagePath CONTAINS "/Sandbox")) OR (subsystem == "com.apple.sandbox.reporting") OR (sender == "Sandbox")'

WORK_DIR="${WORK_DIR:-$(pwd)}"
TRACE_DIR="${TRACE_DIR:-${WORK_DIR}/phases/trace}"
TRACE_LOG_DIR="${TRACE_DIR}/logs"
TRACE_VALIDATION_DIR="${TRACE_DIR}/validation"
TRACE_ISSUES_DIR="${TRACE_DIR}/issues"
TRACE_METRICS="${TRACE_DIR}/metrics.jsonl"
TRACE_STATUS="${TRACE_DIR}/status.json"
TRACE_BAD_RULES="${TRACE_DIR}/bad_rules.txt"
TRACE_LAST_RULE="${TRACE_DIR}/last_rule.txt"
WORK_DIR_PARAM="${WORK_DIR_PARAM:-WORK_DIR}"
DYLD_LOG_PATH="${DYLD_LOG_PATH:-${WORK_DIR}/dyld.log}"
DYLD_LOG_PARAM="${DYLD_LOG_PARAM:-DYLD_LOG_PATH}"
MAX_ITERS="${MAX_ITERS:-50}"
SUCCESS_CODE="${SUCCESS_CODE:-0}"
SUCCESS_STREAK="${SUCCESS_STREAK:-2}"
LOG_FLUSH_SECONDS="${LOG_FLUSH_SECONDS:-5}"
SEED_DYLD="${SEED_DYLD:-1}"
LOG_SHOW_WINDOW="${LOG_SHOW_WINDOW:-2m}"
DENY_EXTRACTOR="${ROOT_DIR}/scripts/extract_denies.py"
SANDBOX_MESSAGES="${ROOT_DIR}/scripts/extract_sandbox_messages.py"
DENY_SIGSTOP="${DENY_SIGSTOP:-0}"
ALLOW_FIXTURE_EXEC="${ALLOW_FIXTURE_EXEC:-1}"
IMPORT_DYLD_SUPPORT="${IMPORT_DYLD_SUPPORT:-1}"
DYLD_LOG="${DYLD_LOG:-0}"
DYLD_SUPPORT_PATH="/System/Library/Sandbox/Profiles/dyld-support.sb"
NETWORK_RULES="${NETWORK_RULES:-parsed}"
DENY_SCOPE="${DENY_SCOPE:-all}"
PARAM_ARGS=(-D "${WORK_DIR_PARAM}=${WORK_DIR}" -D "${DYLD_LOG_PARAM}=${DYLD_LOG_PATH}")

repo_rel() {
  TARGET_PATH="$1" PYTHONPATH="${REPO_ROOT}" python3 - <<'PY'
import os
from book.api import path_utils

print(path_utils.to_repo_relative(os.environ["TARGET_PATH"]))
PY
}

write_status_json() {
  local status="$1"
  local iter="$2"
  local reason="${3:-}"
  local issue_dir="${4:-}"
  local preflight_rc="${5:-}"
  local preflight_json="${6:-}"
  local success_streak="${7:-}"
  local return_code="${8:-}"
  local new_rules="${9:-}"
  local denies_seen="${10:-}"
  TRACE_STATUS_PATH="${TRACE_STATUS}" \
    TRACE_STATUS_VALUE="${status}" \
    TRACE_STATUS_ITER="${iter}" \
    TRACE_STATUS_REASON="${reason}" \
    TRACE_STATUS_ISSUE_DIR="${issue_dir}" \
    TRACE_PREFLIGHT_RC="${preflight_rc}" \
    TRACE_PREFLIGHT_JSON="${preflight_json}" \
    TRACE_SUCCESS_STREAK="${success_streak}" \
    TRACE_RETURN_CODE="${return_code}" \
    TRACE_NEW_RULES="${new_rules}" \
    TRACE_DENIES_SEEN="${denies_seen}" \
    PYTHONPATH="${REPO_ROOT}" python3 - <<'PY'
import json
import os
from pathlib import Path

def maybe_int(val: str | None):
    if val in (None, ""):
        return None
    try:
        return int(val)
    except ValueError:
        return val

data = {"status": os.environ.get("TRACE_STATUS_VALUE", "unknown")}
iter_val = maybe_int(os.environ.get("TRACE_STATUS_ITER"))
if iter_val is not None:
    data["iter"] = iter_val
reason = os.environ.get("TRACE_STATUS_REASON")
if reason:
    data["reason"] = reason
issue_dir = os.environ.get("TRACE_STATUS_ISSUE_DIR")
if issue_dir:
    data["issue_dir"] = issue_dir
preflight_rc = maybe_int(os.environ.get("TRACE_PREFLIGHT_RC"))
if preflight_rc is not None:
    data["preflight_rc"] = preflight_rc
preflight_json = os.environ.get("TRACE_PREFLIGHT_JSON")
if preflight_json:
    data["preflight_json"] = preflight_json
success_streak = maybe_int(os.environ.get("TRACE_SUCCESS_STREAK"))
if success_streak is not None:
    data["success_streak"] = success_streak
return_code = maybe_int(os.environ.get("TRACE_RETURN_CODE"))
if return_code is not None:
    data["return_code"] = return_code
new_rules = maybe_int(os.environ.get("TRACE_NEW_RULES"))
if new_rules is not None:
    data["new_rules"] = new_rules
denies_seen = maybe_int(os.environ.get("TRACE_DENIES_SEEN"))
if denies_seen is not None:
    data["denies_seen"] = denies_seen
Path(os.environ["TRACE_STATUS_PATH"]).write_text(json.dumps(data, indent=2, sort_keys=True))
PY
}

SANDBOX_PROFILE_REL="$(repo_rel "${SANDBOX_PROFILE}")"

mkdir -p "${TRACE_LOG_DIR}" "${TRACE_VALIDATION_DIR}" "${TRACE_ISSUES_DIR}"
: > "${TRACE_BAD_RULES}"
: > "${TRACE_LAST_RULE}"

# Initialize profile if missing (same shape as upstream, with optional dyld seed). :contentReference[oaicite:13]{index=13}
if [[ ! -f "${SANDBOX_PROFILE}" ]]; then
  if [[ "${DENY_SIGSTOP}" -eq 1 ]]; then
    DENY_DEFAULT_LINE="(deny default (with send-signal SIGSTOP))"
  else
    DENY_DEFAULT_LINE="(deny default)"
  fi
  if [[ "${SEED_DYLD}" -eq 1 ]]; then
    cat > "${SANDBOX_PROFILE}" <<EOF
(version 1)
(debug deny)
EOF
    if [[ "${IMPORT_DYLD_SUPPORT}" -eq 1 && -f "${DYLD_SUPPORT_PATH}" ]]; then
      echo '(import "dyld-support.sb")' >> "${SANDBOX_PROFILE}"
    else
      cat >> "${SANDBOX_PROFILE}" <<'EOF'
(allow file-read* file-map-executable
  (subpath "/System/Library/Frameworks")
  (subpath "/System/Library/PrivateFrameworks")
  (subpath "/usr/lib")
  (subpath "/System/Library/dyld")
)
(allow file-read* file-map-executable
  (subpath "/System/Cryptexes/App")
  (subpath "/System/Cryptexes/OS")
  (subpath "/System/Volumes/Preboot/Cryptexes/App/System")
  (subpath "/System/Volumes/Preboot/Cryptexes/OS")
)
(allow file-read* file-map-executable
  (subpath "/private/var/db/dyld")
)
EOF
    fi
    cat >> "${SANDBOX_PROFILE}" <<EOF
${DENY_DEFAULT_LINE}
(allow file-read-metadata (subpath "/"))
(allow file-read* (literal "/dev/random") (literal "/dev/urandom"))
(allow file-read* file-write-data (literal "/dev/null") (literal "/dev/zero"))
(allow mach-lookup (global-name "com.apple.system.DirectoryService.libinfo_v1"))
EOF
    if [[ "${ALLOW_FIXTURE_EXEC}" -eq 1 ]]; then
      cat >> "${SANDBOX_PROFILE}" <<EOF
(allow process-exec* (subpath (param "${WORK_DIR_PARAM}")))
(allow file-read-metadata (subpath (param "${WORK_DIR_PARAM}")))
EOF
    fi
    echo "(allow file-write* (literal (param \"${DYLD_LOG_PARAM}\")))" >> "${SANDBOX_PROFILE}"
  else
    cat > "${SANDBOX_PROFILE}" <<EOF
(version 1)
(debug deny)
${DENY_DEFAULT_LINE}
EOF
    if [[ "${ALLOW_FIXTURE_EXEC}" -eq 1 ]]; then
      cat >> "${SANDBOX_PROFILE}" <<EOF
(allow process-exec* (subpath (param "${WORK_DIR_PARAM}")))
(allow file-read-metadata (subpath (param "${WORK_DIR_PARAM}")))
EOF
    fi
    echo "(allow file-write* (literal (param \"${DYLD_LOG_PARAM}\")))" >> "${SANDBOX_PROFILE}"
  fi
fi

: > "${TRACE_METRICS}"

iter=0
success_count=0
while true; do
  iter=$((iter + 1))
  if (( iter > MAX_ITERS )); then
    echo "[!] Reached MAX_ITERS=${MAX_ITERS}; stopping."
    write_status_json "max_iters" "$((iter - 1))" "max_iters"
    break
  fi

  iter_preflight="${TRACE_LOG_DIR}/iter_${iter}_preflight.json"
  if (cd "${REPO_ROOT}" && python3 "${PREFLIGHT_TOOL}" scan "${SANDBOX_PROFILE_REL}" > "${iter_preflight}"); then
    :
  else
    preflight_rc=$?
    echo "[!] Preflight scan failed (rc=${preflight_rc}); stopping. See ${iter_preflight}"
    iter_preflight_rel="$(repo_rel "${iter_preflight}")"
    write_status_json "preflight_failed" "${iter}" "preflight_failed" "" "${preflight_rc}" "${iter_preflight_rel}"
    break
  fi

  iter_log="${TRACE_LOG_DIR}/iter_${iter}.log"
  iter_stdout="${TRACE_LOG_DIR}/iter_${iter}_stdout.txt"
  iter_stderr="${TRACE_LOG_DIR}/iter_${iter}_stderr.txt"
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
  if [[ "${DYLD_LOG}" -eq 1 ]]; then
    DYLD_PRINT_TO_FILE="${DYLD_LOG_PATH}" \
      DYLD_PRINT_LIBRARIES=1 \
      DYLD_PRINT_INITIALIZERS=1 \
      sandbox-exec "${PARAM_ARGS[@]}" -f "${SANDBOX_PROFILE}" "${PROGRAM_NAME}" > "${iter_stdout}" 2> "${iter_stderr}" &
  else
    sandbox-exec "${PARAM_ARGS[@]}" -f "${SANDBOX_PROFILE}" "${PROGRAM_NAME}" > "${iter_stdout}" 2> "${iter_stderr}" &
  fi
  PROGRAM_PID=$!
  echo "${PROGRAM_PID}" > "${TRACE_LOG_DIR}/iter_${iter}_pid.txt"
  if [[ "${DENY_SIGSTOP}" -eq 1 ]]; then
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      state="$(ps -o state= -p "${PROGRAM_PID}" 2>/dev/null | tr -d ' ')"
      if [[ "${state}" == *T* ]]; then
        echo "[!] ${PROGRAM_PID} is stopped (SIGSTOP). Attach debugger with: lldb -p ${PROGRAM_PID}"
        echo "[!] Resume with: kill -CONT ${PROGRAM_PID}"
        break
      fi
      sleep 0.2
    done
  fi

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

  if [[ "${RETURN_CODE}" -eq 65 ]]; then
    after_lines="$(wc -l < "${SANDBOX_PROFILE}" | tr -d ' ')"
    printf '{"iter":%s,"return_code":%s,"denies_seen":0,"new_rules":0,"profile_lines":%s}\n' \
      "${iter}" "${RETURN_CODE}" "${after_lines}" >> "${TRACE_METRICS}"
    invalid_dir="${TRACE_ISSUES_DIR}/profile_invalid_iter_${iter}"
    mkdir -p "${invalid_dir}"
    cp "${SANDBOX_PROFILE}" "${invalid_dir}/profile.sb"
    cp "${iter_log}" "${invalid_dir}/iter_${iter}.log"
    cp "${iter_preflight}" "${invalid_dir}/iter_${iter}_preflight.json"
    cp "${iter_stdout}" "${invalid_dir}/iter_${iter}_stdout.txt"
    cp "${iter_stderr}" "${invalid_dir}/iter_${iter}_stderr.txt"
    cp "${TRACE_BAD_RULES}" "${invalid_dir}/bad_rules.txt"
    cp "${TRACE_LAST_RULE}" "${invalid_dir}/last_appended_rule.txt"
    /usr/bin/log show --last "${LOG_SHOW_WINDOW}" --style json --predicate "${LOG_PREDICATE}" > "${invalid_dir}/log_show.json" 2>/dev/null || true
    python3 "${SANDBOX_MESSAGES}" "${iter_log}" > "${invalid_dir}/sandbox_messages.txt" 2>/dev/null || true
    if [[ -f "${invalid_dir}/log_show.json" ]]; then
      python3 "${SANDBOX_MESSAGES}" "${invalid_dir}/log_show.json" >> "${invalid_dir}/sandbox_messages.txt" 2>/dev/null || true
    fi
    echo "[!] Profile invalid (rc=65); bundle: ${invalid_dir}"
    invalid_dir_rel="$(repo_rel "${invalid_dir}")"
    write_status_json "profile_invalid" "${iter}" "profile_invalid" "${invalid_dir_rel}" "" "" "" "${RETURN_CODE}" "0" "0"
    break
  fi

  # Extract deny lines from JSON eventMessage fields (all sandbox messages in-window).
  deny_lines_tmp="$(mktemp)"
  deny_arg="${DENY_SCOPE}"
  if [[ "${DENY_SCOPE}" == "pid" ]]; then
    deny_arg="${PROGRAM_PID}"
  fi
  python3 "${DENY_EXTRACTOR}" "${iter_log}" "${deny_arg}" > "${deny_lines_tmp}"
  denies_seen="$(wc -l < "${deny_lines_tmp}" | tr -d ' ')"
  if [[ "${denies_seen}" -eq 0 ]]; then
    iter_log_show="${TRACE_LOG_DIR}/iter_${iter}_log_show.json"
    sleep 1
    /usr/bin/log show --last "${LOG_SHOW_WINDOW}" --style json --predicate "${LOG_PREDICATE}" > "${iter_log_show}" 2>/dev/null || true
    python3 "${DENY_EXTRACTOR}" "${iter_log_show}" "${deny_arg}" > "${deny_lines_tmp}"
    denies_seen="$(wc -l < "${deny_lines_tmp}" | tr -d ' ')"
  fi

  new_rules=0
  while IFS= read -r line; do
    op=""
    arg=""
    if [[ "${line}" =~ deny\([0-9]+\)\ ([^ ]+)\ (.+)$ ]]; then
      op="${BASH_REMATCH[1]}"
      arg="${BASH_REMATCH[2]}"
    elif [[ "${line}" =~ deny\([0-9]+\)\ ([^ ]+)$ ]]; then
      op="${BASH_REMATCH[1]}"
      arg=""
    else
      continue
    fi

    rule=""
    if [[ "${op}" == network-* ]]; then
      case "${NETWORK_RULES}" in
        drop)
          echo "dropped_network: ${line}" >> "${TRACE_BAD_RULES}"
          continue
          ;;
        coarse)
          rule="(allow ${op})"
          ;;
        parsed)
          scope="remote"
          if [[ "${op}" == "network-bind" || "${op}" == "network-listen" ]]; then
            scope="local"
          fi

          raw="${arg}"
          while [[ "${raw}" == remote:* || "${raw}" == local:* ]]; do
            raw="${raw#remote:}"
            raw="${raw#local:}"
          done

          path_arg=""
          if [[ "${raw}" == path:* ]]; then
            path_arg="${raw#path:}"
          elif [[ "${raw}" == unix-socket:* ]]; then
            path_arg="${raw#unix-socket:}"
          elif [[ "${raw}" == /* ]]; then
            path_arg="${raw}"
          fi

          if [[ -n "${path_arg}" ]]; then
            rule="(allow ${op} (${scope} unix-socket (path-literal \"${path_arg}\")))"
          else
            host="*"
            port="*"
            if [[ -n "${raw}" ]]; then
              if [[ "${raw}" == *":"* ]]; then
                port="${raw##*:}"
                host="${raw%:*}"
              else
                host="${raw}"
                port="*"
              fi
              if [[ -z "${port}" || ( ! "${port}" =~ ^[0-9]+$ && "${port}" != "*" ) ]]; then
                port="*"
              fi
              if [[ -z "${host}" || "${host}" == "*" ]]; then
                host="*"
              elif [[ "${host}" == "localhost" || "${host}" == "127.0.0.1" || "${host}" == "::1" ]]; then
                host="localhost"
              else
                host="*"
              fi
            fi
            rule="(allow ${op} (${scope} ip \"${host}:${port}\"))"
          fi
          ;;
        *)
          rule="(allow ${op})"
          ;;
      esac
    else
      if [[ -z "${arg}" ]]; then
        rule="(allow ${op})"
      else
        if [[ "${arg}" == path:* ]]; then
          arg="${arg#path:}"
        fi
        if [[ "${op}" == sysctl-* ]]; then
          rule="(allow ${op} (sysctl-name \"${arg}\"))"
        elif [[ "${op}" == mach-lookup ]]; then
          rule="(allow ${op} (global-name \"${arg}\"))"
        else
          rule="(allow ${op} (literal \"${arg}\"))"
        fi
      fi
    fi

    if [[ -z "${rule}" ]]; then
      continue
    fi

    # Only append if the exact line is not already present.
    if ! grep -Fqx "${rule}" "${SANDBOX_PROFILE}"; then
      tmp_profile="$(mktemp "${WORK_DIR}/profile.tmp.XXXX")"
      cp "${SANDBOX_PROFILE}" "${tmp_profile}"
      echo "${rule}" >> "${tmp_profile}"
      set +e
      sandbox-exec "${PARAM_ARGS[@]}" -f "${tmp_profile}" /usr/bin/true >/dev/null 2>&1
      validate_rc=$?
      set -e
      rm -f "${tmp_profile}"
      if [[ "${validate_rc}" -eq 65 ]]; then
        echo "invalid_rule: ${rule}" >> "${TRACE_BAD_RULES}"
        continue
      fi
      echo "${rule}" >> "${SANDBOX_PROFILE}"
      echo "${rule}" > "${TRACE_LAST_RULE}"
      new_rules=$((new_rules + 1))
    fi
  done < "${deny_lines_tmp}"
  rm -f "${deny_lines_tmp}"

  after_lines="$(wc -l < "${SANDBOX_PROFILE}" | tr -d ' ')"
  printf '{"iter":%s,"return_code":%s,"denies_seen":%s,"new_rules":%s,"profile_lines":%s}\n' \
    "${iter}" "${RETURN_CODE}" "${denies_seen}" "${new_rules}" "${after_lines}" >> "${TRACE_METRICS}"

  echo "[-] Iteration ${iter} done: rc=${RETURN_CODE}, denies=${denies_seen}, new_rules=${new_rules}, lines=${after_lines}"

  # Stop conditions: success streak, continue if rules added, otherwise record a stall/no-new-rules reason.
  if [[ "${RETURN_CODE}" -eq "${SUCCESS_CODE}" && "${new_rules}" -eq 0 ]]; then
    success_count=$((success_count + 1))
  else
    success_count=0
  fi
  if [[ "${success_count}" -ge "${SUCCESS_STREAK}" ]]; then
    echo "[+] Success streak ${success_count}/${SUCCESS_STREAK}; stopping."
    write_status_json "success" "${iter}" "success_streak" "" "" "" "${SUCCESS_STREAK}" "${RETURN_CODE}" "${new_rules}" "${denies_seen}"
    break
  fi
  if [[ "${new_rules}" -gt 0 ]]; then
    continue
  fi
  if [[ "${RETURN_CODE}" -eq "${SUCCESS_CODE}" && "${new_rules}" -eq 0 ]]; then
    echo "[-] Success with no new rules; streak ${success_count}/${SUCCESS_STREAK}. Continuing."
    continue
  fi

  if [[ "${RETURN_CODE}" -ge 128 ]]; then
    stall_dir="${TRACE_ISSUES_DIR}/stall_iter_${iter}"
    mkdir -p "${stall_dir}"
    cp "${SANDBOX_PROFILE}" "${stall_dir}/profile.sb"
    cp "${iter_log}" "${stall_dir}/iter_${iter}.log"
    cp "${iter_preflight}" "${stall_dir}/iter_${iter}_preflight.json"
    cp "${iter_stdout}" "${stall_dir}/iter_${iter}_stdout.txt"
    cp "${iter_stderr}" "${stall_dir}/iter_${iter}_stderr.txt"
    if [[ -f "${WORK_DIR}/dyld.log" ]]; then
      cp "${WORK_DIR}/dyld.log" "${stall_dir}/"
    fi
    echo "rc=${RETURN_CODE}" > "${stall_dir}/reason.txt"
    echo "new_rules=${new_rules}" >> "${stall_dir}/reason.txt"
    echo "denies_seen=${denies_seen}" >> "${stall_dir}/reason.txt"

    /usr/bin/log show --last 2m --style json --predicate "${LOG_PREDICATE}" > "${stall_dir}/log_show.json" 2>/dev/null || true
    python3 "${SANDBOX_MESSAGES}" "${iter_log}" > "${stall_dir}/sandbox_messages.txt" 2>/dev/null || true
    if [[ -f "${stall_dir}/log_show.json" ]]; then
      python3 "${SANDBOX_MESSAGES}" "${stall_dir}/log_show.json" >> "${stall_dir}/sandbox_messages.txt" 2>/dev/null || true
    fi

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
    stall_dir_rel="$(repo_rel "${stall_dir}")"
    write_status_json "stalled" "${iter}" "signal_abort" "${stall_dir_rel}" "" "" "" "${RETURN_CODE}" "${new_rules}" "${denies_seen}"
    break
  fi

  echo "[*] No new rules added; stopping."
  write_status_json "no_new_rules" "${iter}" "no_new_rules" "" "" "" "" "${RETURN_CODE}" "${new_rules}" "${denies_seen}"
  break
done

echo "Updated sandbox profile: ${SANDBOX_PROFILE}"
