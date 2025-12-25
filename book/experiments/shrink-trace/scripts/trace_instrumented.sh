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
SANDBOX_MESSAGES="${ROOT_DIR}/scripts/extract_sandbox_messages.py"
DENY_SIGSTOP="${DENY_SIGSTOP:-0}"
ALLOW_FIXTURE_EXEC="${ALLOW_FIXTURE_EXEC:-1}"
IMPORT_DYLD_SUPPORT="${IMPORT_DYLD_SUPPORT:-1}"
DYLD_LOG="${DYLD_LOG:-0}"
DYLD_SUPPORT_PATH="/System/Library/Sandbox/Profiles/dyld-support.sb"
NETWORK_RULES="${NETWORK_RULES:-drop}"
BAD_RULES="${WORK_DIR}/bad_rules.txt"
LAST_RULE_FILE="${WORK_DIR}/last_appended_rule.txt"

mkdir -p "${LOG_DIR}"
: > "${TRACE_STATUS}"
: > "${BAD_RULES}"
: > "${LAST_RULE_FILE}"

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
(allow process-exec* (subpath "${WORK_DIR}"))
(allow file-read-metadata (subpath "${WORK_DIR}"))
EOF
    fi
    echo "(allow file-write* (literal \"${WORK_DIR}/dyld.log\"))" >> "${SANDBOX_PROFILE}"
  else
    cat > "${SANDBOX_PROFILE}" <<EOF
(version 1)
(debug deny)
${DENY_DEFAULT_LINE}
EOF
    if [[ "${ALLOW_FIXTURE_EXEC}" -eq 1 ]]; then
      cat >> "${SANDBOX_PROFILE}" <<EOF
(allow process-exec* (subpath "${WORK_DIR}"))
(allow file-read-metadata (subpath "${WORK_DIR}"))
EOF
    fi
    echo "(allow file-write* (literal \"${WORK_DIR}/dyld.log\"))" >> "${SANDBOX_PROFILE}"
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
  if [[ "${DYLD_LOG}" -eq 1 ]]; then
    DYLD_PRINT_TO_FILE="${WORK_DIR}/dyld.log" \
      DYLD_PRINT_LIBRARIES=1 \
      DYLD_PRINT_INITIALIZERS=1 \
      sandbox-exec -f "${SANDBOX_PROFILE}" "${PROGRAM_NAME}" > "${iter_stdout}" 2> "${iter_stderr}" &
  else
    sandbox-exec -f "${SANDBOX_PROFILE}" "${PROGRAM_NAME}" > "${iter_stdout}" 2> "${iter_stderr}" &
  fi
  PROGRAM_PID=$!
  echo "${PROGRAM_PID}" > "${LOG_DIR}/iter_${iter}_pid.txt"
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
    echo -e "${iter}\t${RETURN_CODE}\t0\t0\t${after_lines}" >> "${METRICS_TSV}"
    invalid_dir="${WORK_DIR}/profile_invalid_iter_${iter}"
    mkdir -p "${invalid_dir}"
    cp "${SANDBOX_PROFILE}" "${invalid_dir}/profile.sb"
    cp "${iter_log}" "${invalid_dir}/iter_${iter}.log"
    cp "${iter_preflight}" "${invalid_dir}/iter_${iter}_preflight.json"
    cp "${iter_stdout}" "${invalid_dir}/iter_${iter}_stdout.txt"
    cp "${iter_stderr}" "${invalid_dir}/iter_${iter}_stderr.txt"
    cp "${BAD_RULES}" "${invalid_dir}/bad_rules.txt"
    cp "${LAST_RULE_FILE}" "${invalid_dir}/last_appended_rule.txt"
    /usr/bin/log show --last "${LOG_SHOW_WINDOW}" --style json --predicate "${LOG_PREDICATE}" > "${invalid_dir}/log_show.json" 2>/dev/null || true
    python3 "${SANDBOX_MESSAGES}" "${iter_log}" > "${invalid_dir}/sandbox_messages.txt" 2>/dev/null || true
    if [[ -f "${invalid_dir}/log_show.json" ]]; then
      python3 "${SANDBOX_MESSAGES}" "${invalid_dir}/log_show.json" >> "${invalid_dir}/sandbox_messages.txt" 2>/dev/null || true
    fi
    echo "[!] Profile invalid (rc=65); bundle: ${invalid_dir}"
    echo "status=profile_invalid" > "${TRACE_STATUS}"
    echo "iter=${iter}" >> "${TRACE_STATUS}"
    echo "invalid_dir=${invalid_dir}" >> "${TRACE_STATUS}"
    break
  fi

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
          echo "dropped_network: ${line}" >> "${BAD_RULES}"
          continue
          ;;
        coarse)
          rule="(allow ${op})"
          ;;
        parsed)
          if [[ -z "${arg}" || "${arg}" == path:* || "${arg}" == unix-socket:* || "${arg}" == *"/"* ]]; then
            rule="(allow ${op})"
          else
            raw="${arg#remote:}"
            raw="${raw#local:}"
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
            elif [[ "${host}" == *":"* ]]; then
              host="*"
            else
              host="*"
            fi
            scope="remote"
            if [[ "${op}" == "network-bind" || "${op}" == "network-listen" ]]; then
              scope="local"
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
      sandbox-exec -f "${tmp_profile}" /usr/bin/true >/dev/null 2>&1
      validate_rc=$?
      set -e
      rm -f "${tmp_profile}"
      if [[ "${validate_rc}" -eq 65 ]]; then
        echo "invalid_rule: ${rule}" >> "${BAD_RULES}"
        continue
      fi
      echo "${rule}" >> "${SANDBOX_PROFILE}"
      echo "${rule}" > "${LAST_RULE_FILE}"
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
