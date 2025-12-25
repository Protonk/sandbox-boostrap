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

PROFILE="${RUN_DIR}/profile.sb"
SHRUNK="${RUN_DIR}/profile.sb.shrunk"
METRICS="${RUN_DIR}/metrics.tsv"

echo "[*] Summary for: ${RUN_DIR}"

if [[ -f "${METRICS}" ]]; then
  echo "== Iterations =="
  tail -n +2 "${METRICS}" | wc -l | awk '{print "iterations:", $1}'
  echo
  echo "== Final trace row =="
  tail -n 1 "${METRICS}"
  echo
fi

if [[ -f "${PROFILE}" ]]; then
  echo "profile.sb lines: $(wc -l < "${PROFILE}" | tr -d ' ')"
fi
if [[ -f "${SHRUNK}" ]]; then
  echo "profile.sb.shrunk lines: $(wc -l < "${SHRUNK}" | tr -d ' ')"
fi

if [[ -f "${RUN_DIR}/shrink_stdout.txt" ]]; then
  echo
  echo "shrink removed count: $(grep -c 'Removed line' "${RUN_DIR}/shrink_stdout.txt" || true)"
  echo "shrink kept count:    $(grep -c 'Kept line' "${RUN_DIR}/shrink_stdout.txt" || true)"
fi
