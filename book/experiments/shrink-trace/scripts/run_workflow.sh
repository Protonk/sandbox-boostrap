#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/out"
REPO_ROOT="$(cd "${ROOT_DIR}/../../.." && pwd)"
PROFILE_REL="book/experiments/shrink-trace/out/profile.sb"
SEED_DYLD="${SEED_DYLD:-1}"

if [[ -d "${OUT_DIR}" ]]; then
  rm -rf "${OUT_DIR:?}"
fi
mkdir -p "${OUT_DIR}"

echo "[*] Output dir: ${OUT_DIR}"

# Build fixture into book/experiments/shrink-trace/out/sandbox_target
"${ROOT_DIR}/scripts/build_fixture.sh"

# Ensure the program name resolves without a path, so killall behavior (if you run upstream)
# would match a process name. Here it also keeps command lines tidy.
export PATH="${OUT_DIR}:${PATH}"
export SEED_DYLD

PROFILE="${OUT_DIR}/profile.sb"
TRACE_STATUS="${OUT_DIR}/trace_status.txt"

echo "[*] Tracing to build profile: ${PROFILE}"
(
  cd "${OUT_DIR}"
  "${ROOT_DIR}/scripts/trace_instrumented.sh" ./sandbox_target "${PROFILE}" | tee "${OUT_DIR}/trace_stdout.txt"
)

trace_status="unknown"
stall_dir=""
if [[ -f "${TRACE_STATUS}" ]]; then
  trace_status="$(awk -F= '/^status=/{print $2}' "${TRACE_STATUS}" | tail -n 1)"
  stall_dir="$(awk -F= '/^stall_dir=/{print $2}' "${TRACE_STATUS}" | tail -n 1)"
fi

if [[ "${trace_status}" != "success" ]]; then
  echo "[!] Trace status: ${trace_status}; skipping shrink."
  if [[ -n "${stall_dir}" ]]; then
    echo "[!] Stall bundle: ${stall_dir}"
  fi
  exit 0
fi

echo "[*] Preflight scan (trace profile)"
if (cd "${REPO_ROOT}" && python3 book/tools/preflight/preflight.py scan "${PROFILE_REL}" > "${OUT_DIR}/preflight_scan.json"); then
  :
else
  preflight_rc=$?
  echo "[!] Preflight scan failed (rc=${preflight_rc}); see ${OUT_DIR}/preflight_scan.json"
  exit "${preflight_rc}"
fi

echo "[*] Preflight scan OK; proceeding to shrink"
echo "[*] Shrinking profile"

(
  cd "${OUT_DIR}"
  "${ROOT_DIR}/upstream/shrink.sh" ./sandbox_target "${PROFILE}" | tee "${OUT_DIR}/shrink_stdout.txt"
)

echo "[*] Verifying shrunk profile"
(
  cd "${OUT_DIR}"
  sandbox-exec -f "${PROFILE}.shrunk" ./sandbox_target
)

echo "[+] Done. Outputs:"
echo "    ${OUT_DIR}/profile.sb"
echo "    ${OUT_DIR}/profile.sb.shrunk"
echo "    ${OUT_DIR}/metrics.tsv"
echo "    ${OUT_DIR}/logs/"
echo "    ${OUT_DIR}/trace_stdout.txt"
echo "    ${OUT_DIR}/shrink_stdout.txt"
