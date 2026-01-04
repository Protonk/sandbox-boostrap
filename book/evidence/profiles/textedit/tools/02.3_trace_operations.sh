#!/bin/zsh
# Scaffold for Section 2.3 ("Tracing real operations through the sandbox").
# Safe to run: defaults to dry-run and only echoes intended tracing commands.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
BASE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
TRACES_DIR="${BASE_DIR}/traces"
mkdir -p "${TRACES_DIR}"

usage() {
  cat <<'USAGE'
Usage: 02.3_trace_operations.sh [--dry-run|--run|--help]

Default (no args or --dry-run):
  Print intended tracing commands without executing them.

--run:
  Execute a safe placeholder capture (echo to a trace file) so humans can
  swap in real fs_usage/opensnoop commands on macOS.

Actions -> interesting traces:
- Open file in ~/Documents: file opens in user paths; mach-lookup to tccd expected.
- Auto-save to container: writes under container Data/Documents; temp files.
- Print document: printing service interactions; possible sandbox extensions.

Outputs live under profiles/textedit/traces/.
USAGE
}

mode="dry-run"
case "${1:-}" in
  ""|--dry-run) mode="dry-run" ;;
  --run) mode="run" ;;
  --help) usage; exit 0 ;;
  *) echo "Unknown option: ${1}"; usage; exit 1 ;;
esac

echo "Mode: ${mode}"
echo "Traces directory: ${TRACES_DIR}"

planned_commands() {
  cat <<'CMDS'
# Example fs_usage capture (macOS only; requires sudo):
#   sudo fs_usage -w -f filesys -t 5 | tee "profiles/textedit/traces/fs_usage_sample.txt"
# Example opensnoop capture for TextEdit PID:
#   sudo opensnoop -p <TextEditPID> | tee "profiles/textedit/traces/opensnoop_sample.txt"
# Future sandbox-aware tracer placeholder:
#   sudo /path/to/sandbox_tracer --pid <TextEditPID> --output profiles/textedit/traces/sandbox_trace.json

# Start TextEdit for correlation (manual on macOS):
#   open -a /System/Applications/TextEdit.app
CMDS
}

planned_commands

if [[ "${mode}" == "dry-run" ]]; then
  echo "Dry-run complete. Replace placeholders above when running on macOS."
  exit 0
fi

echo "Running placeholder capture (no real tracing)..."
placeholder_path="${TRACES_DIR}/run_placeholder.txt"
echo "Placeholder run at $(date)" > "${placeholder_path}"
echo "Replace this with fs_usage/opensnoop captures on macOS." >> "${placeholder_path}"
echo "Wrote placeholder trace file to ${placeholder_path}"
