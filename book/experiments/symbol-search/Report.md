# Symbol Search – Research Report

## Purpose
Locate the sandbox PolicyGraph dispatcher (and helpers) in the KC by combining AppleMatch/sandbox string and import pivots with MACF hook traces and op-table structure checks.

## Baseline & tooling
- Host: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (Apple Silicon, SIP on).
- Inputs: `book/dumps/ghidra/private/aapl-restricted/14.4.1-23E224/kernel/BootKernelExtensions.kc`; analyzed Ghidra project `book/dumps/ghidra/projects/sandbox_14.4.1-23E224`.
- Tools: `book/api/ghidra/run_task.py` tasks (`kernel-string-refs`, `kernel-data-define`, `kernel-op-table`, etc.), ARM64 processor with `disable_x86_analyzers.py`; repo-local JAVA/HOME/TMPDIR (`JAVA_TOOL_OPTIONS=-Duser.home=$PWD/book/dumps/ghidra/user -Djava.io.tmpdir=$PWD/book/dumps/ghidra/tmp`).

## Current status
- Import census: unfiltered `kernel-imports` (imports_all.json) plus filtered view (`filter_imports.py --substr applematch mac_policy sandbox seatbelt`) show 0 matching externals. Import/GOT anchors for these names are ok-negative on this world.
- String sweep: `kernel-string-refs` (clean argv, `extlib=`) yields 190 string hits, 0 symbol hits, 0 externals; all references are LINKEDIT-only. MACF/AppleMatch/sandbox evidence via names is string-table-only and not referenced from code or data.
- Data/XREF probes: `kernel-data-define` on sandbox strings and op-table starts resolves to two strings (no callers) and four pointers to `0xffffff8000100000`; one LINKEDIT data ref at `0x-7ffc3311d0` (no function). `kernel_imm_search` for mac_policy_init and _mac_policy_register string addresses returned 0 hits. No mac_policy_conf/mac_policy_ops struct or mpo_* helper located.
- Op-table context: earlier pointer-table sweeps still show dense 512-entry tables (e.g., `__const` 0x-7fffdae120) but with no recorded callers; linkage to a dispatcher is speculative.
- Dispatcher scan: `kernel-tag-switch` and ARM64 ADRP scans on `BootKernelExtensions.kc` currently yield 0 candidates/0 ADRPs; instruction-level disassembly appears absent in this project.
- BootKernelCollection import: analysis-only run completed (about 2206s) and saved the project `sandbox_14.4.1-23E224_kc`. PostScript passes are now available and show that sandbox-named memory blocks do not exist in this KC; tag-switch over all blocks yields a very large candidate set.
- Jump-table extraction: `kernel_jump_table_dump.py` on `FUN_fffffe00092fb9e0` produced 11 tables with explicit ranges (for example, base 0x150 with count 0x3d) and offsets into the same function; this looks like a multi-range dispatcher but is not yet tied to a sandbox witness.
- Pointer table context: the sole data ref to `FUN_fffffe00092fb9e0` lands inside a dense pointer table in `__const` (`0xfffffe0007ca4040`), with adjacent entries pointing to nearby functions.
- Pointer table bounds: auto expansion finds a 709-entry table spanning `0xfffffe0007ca3360–0xfffffe0007ca4980` in `__const`, with targets in `__text` and null terminators at both ends.

## Findings (status-aware)
- AppleMatch pivot: ok-negative for imports (full census shows no externals); partial/brittle for strings (LINKEDIT-only, no callers).
- mac_policy_conf/mac_policy_ops: blocked — no struct or mpo_* helper resolved; data-define/XREFs were empty and imm-search for key strings returned 0 hits.
- Dispatcher linkage: under exploration - the BootKernelCollection tag-switch run found a high-density jump-table function `FUN_fffffe00092fb9e0` (multiple ADRP+ADD+LDRSW+ADR+ADD+BR sequences keyed off `w22`). This is a plausible dispatcher candidate but currently lacks a sandbox-specific witness and is referenced only via a pointer in `__const`.
- BootKernelCollection string pivots: partial/brittle - 3 string hits for AppleMatch/Sandbox identifiers, 0 references; ADRP scans for those string addresses returned 0 matches.
- Jump-table tables: under exploration - 11 tables extracted for `FUN_fffffe00092fb9e0` with range gating (index_base + index_cmp) and targets resolving inside the same function; the tables do not yet identify a sandbox boundary.
- Pointer table bounds: under exploration - the auto-expanded table bounds give a stable range but still lack a sandbox/kext witness to interpret the table’s role.

## Blockers / risks
- BootKernelCollection has no sandbox-named memory blocks; tag-switch scanning falls back to all blocks, yielding 43,722 candidates. We need a kext boundary or alternate anchor to narrow the search.
- The pointer table containing `FUN_fffffe00092fb9e0` is not yet tied to `com.apple.security.sandbox` or mac_policy registration, so the dispatcher candidate remains provisional.

## Open questions
- Where are the AppleMatch entry points (imports or stubs) referenced from sandbox code?
- Where is the sandbox mac_policy_conf/mac_policy_ops registered, and what shared helper do the mpo_* hooks call?
- Do the dense pointer tables align with the promoted op-table layout, and if so, how are they reached at runtime?

## Next steps
1) Close this experiment as ok-negative for kernel imports/symbol anchors; keep string-only evidence documented.
2) Use the pointer table window around `0xfffffe0007ca4040` to determine table bounds and check for nearby metadata or patterns that could anchor it to a specific kext or policy registration path.
3) If the pointer table bounds are found, dump a wider slice and cluster by target range to see if it isolates a sandbox-relevant region.
4) Revisit op-table candidates only after a concrete dispatcher/mac_policy_ops candidate exists; align against `book/graph/mappings/op_table/op_table.json` before running table-materialization scans.
5) If KC analysis remains blocked after mitigation, consider a kext-focused mac_policy registration experiment as the next pivot (defer until KC route is exhausted).

## BootKernelCollection analysis-only run (script)

Run from the repo root with `GHIDRA_HEADLESS` and `JAVA_HOME` set. This builds/refreshes the
`book/dumps/ghidra/projects/sandbox_14.4.1-23E224_kc` project with full analysis and no postScript.

If `JAVA_HOME` is not set, you can set it like this (adjust the version if needed):

```bash
export JAVA_HOME="$(/usr/libexec/java_home -v 21)"
```

If `GHIDRA_HEADLESS` is not set, use the Homebrew path:

```bash
export GHIDRA_HEADLESS="/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless"
```

```bash
bash -s <<'SH'
set -euo pipefail

ROOT="$(pwd)"
if [ ! -f "$ROOT/book/experiments/symbol-search/Report.md" ]; then
  echo "Run from repo root." >&2
  exit 1
fi

BUILD_ID="14.4.1-23E224"
KERNEL_DIR="$ROOT/book/dumps/ghidra/private/aapl-restricted/$BUILD_ID/kernel"
KC="$KERNEL_DIR/BootKernelCollection.kc"
PROJECT="sandbox_${BUILD_ID}_kc"
PROJECTS="$ROOT/book/dumps/ghidra/projects"
SCRIPTS="$ROOT/book/api/ghidra/scripts"
USER_DIR="$ROOT/book/dumps/ghidra/user"
TMP_DIR="$ROOT/book/dumps/ghidra/tmp"
PROC="AARCH64:LE:64:AppleSilicon"
PRE="disable_x86_analyzers.py"

: "${GHIDRA_HEADLESS:?Set GHIDRA_HEADLESS to analyzeHeadless}"
: "${JAVA_HOME:?Set JAVA_HOME to a JDK}"

export HOME="$USER_DIR"
export GHIDRA_USER_HOME="$USER_DIR"
export TMPDIR="$TMP_DIR"
JAVA_TOOL_OPTIONS="-Duser.home=$USER_DIR -Djava.io.tmpdir=$TMP_DIR"
export JAVA_TOOL_OPTIONS

"$GHIDRA_HEADLESS" "$PROJECTS" "$PROJECT" \
  -overwrite \
  -processor "$PROC" \
  -preScript "$PRE" \
  -scriptPath "$SCRIPTS" \
  -import "$KC"
SH
```

## BootKernelCollection postScript runs (block disasm + tag-switch)

Run after the analysis-only pass. These operate on the existing project and do not re-run analysis.

```bash
bash -s <<'SH'
set -euo pipefail

ROOT="$(pwd)"
BUILD_ID="14.4.1-23E224"
PROJECT="sandbox_${BUILD_ID}_kc"
PROJECTS="$ROOT/book/dumps/ghidra/projects"
SCRIPTS="$ROOT/book/api/ghidra/scripts"
OUT_ROOT="$ROOT/book/dumps/ghidra/out/$BUILD_ID"
USER_DIR="$ROOT/book/dumps/ghidra/user"
TMP_DIR="$ROOT/book/dumps/ghidra/tmp"

: "${GHIDRA_HEADLESS:?Set GHIDRA_HEADLESS to analyzeHeadless}"
: "${JAVA_HOME:?Set JAVA_HOME to a JDK}"

export HOME="$USER_DIR"
export GHIDRA_USER_HOME="$USER_DIR"
export TMPDIR="$TMP_DIR"
JAVA_TOOL_OPTIONS="-Duser.home=$USER_DIR -Djava.io.tmpdir=$TMP_DIR"
export JAVA_TOOL_OPTIONS

# Targeted disassembly over sandbox-named executable blocks.
"$GHIDRA_HEADLESS" "$PROJECTS" "$PROJECT" \
  -noanalysis \
  -process BootKernelCollection.kc \
  -scriptPath "$SCRIPTS" \
  -scriptlog "$OUT_ROOT/kernel-block-disasm-kc/script.log" \
  -postScript kernel_block_disasm.py "$OUT_ROOT/kernel-block-disasm-kc" "$BUILD_ID" sandbox 4 0 1

# Dispatcher candidate scan.
"$GHIDRA_HEADLESS" "$PROJECTS" "$PROJECT" \
  -noanalysis \
  -process BootKernelCollection.kc \
  -scriptPath "$SCRIPTS" \
  -scriptlog "$OUT_ROOT/kernel-tag-switch-kc/script.log" \
  -postScript kernel_tag_switch.py "$OUT_ROOT/kernel-tag-switch-kc" "$BUILD_ID"
SH
```

## BootKernelCollection postScript runs (jump-table + pointer window)

Run after the analysis-only pass. These operate on the existing project and do not re-run analysis.

```bash
bash -s <<'SH'
set -euo pipefail

ROOT="$(pwd)"
BUILD_ID="14.4.1-23E224"
PROJECT="sandbox_${BUILD_ID}_kc"
PROJECTS="$ROOT/book/dumps/ghidra/projects"
SCRIPTS="$ROOT/book/api/ghidra/scripts"
OUT_ROOT="$ROOT/book/dumps/ghidra/out/$BUILD_ID"
USER_DIR="$ROOT/book/dumps/ghidra/user"
TMP_DIR="$ROOT/book/dumps/ghidra/tmp"

: "${GHIDRA_HEADLESS:?Set GHIDRA_HEADLESS to analyzeHeadless}"
: "${JAVA_HOME:?Set JAVA_HOME to a JDK}"

export HOME="$USER_DIR"
export GHIDRA_USER_HOME="$USER_DIR"
export TMPDIR="$TMP_DIR"
JAVA_TOOL_OPTIONS="-Duser.home=$USER_DIR -Djava.io.tmpdir=$TMP_DIR"
export JAVA_TOOL_OPTIONS

# Jump-table extraction for the dispatcher candidate.
"$GHIDRA_HEADLESS" "$PROJECTS" "$PROJECT" \
  -noanalysis \
  -process BootKernelCollection.kc \
  -scriptPath "$SCRIPTS" \
  -scriptlog "$OUT_ROOT/kernel-jump-table-dump-kc/script.log" \
  -postScript kernel_jump_table_dump.py "$OUT_ROOT/kernel-jump-table-dump-kc" "$BUILD_ID" FUN_fffffe00092fb9e0 18 512

# Pointer table window around the sole data ref to FUN_fffffe00092fb9e0.
"$GHIDRA_HEADLESS" "$PROJECTS" "$PROJECT" \
  -noanalysis \
  -process BootKernelCollection.kc \
  -scriptPath "$SCRIPTS" \
  -scriptlog "$OUT_ROOT/kernel-pointer-window-kc/script.log" \
  -postScript kernel_pointer_table_window.py "$OUT_ROOT/kernel-pointer-window-kc" "$BUILD_ID" 0xfffffe0007ca4040 128 8 center

# Auto-expand to find table bounds (stop on nulls/block changes).
"$GHIDRA_HEADLESS" "$PROJECTS" "$PROJECT" \
  -noanalysis \
  -process BootKernelCollection.kc \
  -scriptPath "$SCRIPTS" \
  -scriptlog "$OUT_ROOT/kernel-pointer-window-kc-auto/script.log" \
  -postScript kernel_pointer_table_window.py "$OUT_ROOT/kernel-pointer-window-kc-auto" "$BUILD_ID" 0xfffffe0007ca4040 1024 8 auto
SH
```

## Evidence & artifacts (KC postScript)

- Block disasm report: `book/dumps/ghidra/out/14.4.1-23E224/kernel-block-disasm-kc/disasm_report.json`.
- Tag-switch candidates (KC): `book/dumps/ghidra/out/14.4.1-23E224/kernel-tag-switch-kc/switch_candidates.json`.
- Function dumps (KC): `book/dumps/ghidra/out/14.4.1-23E224/kernel-function-dump-kc/function_dump.json`.
- Function info (top candidates): `book/dumps/ghidra/out/14.4.1-23E224/kernel-function-info-kc-top10/function_info.json`.
- String refs (KC): `book/dumps/ghidra/out/14.4.1-23E224/kernel-string-refs-kc/string_references.json`.
- ADRP scans (KC): `book/dumps/ghidra/out/14.4.1-23E224/kernel-adrp-add-kc-0xfffffe0007009f18/adrp_add_scan.json`, `book/dumps/ghidra/out/14.4.1-23E224/kernel-adrp-add-kc-0xfffffe000bf5b8b8/adrp_add_scan.json`, `book/dumps/ghidra/out/14.4.1-23E224/kernel-adrp-add-kc-0xfffffe0007005f98/adrp_add_scan.json`.
- Pointer entry for `FUN_fffffe00092fb9e0`: `book/dumps/ghidra/out/14.4.1-23E224/kernel-addr-lookup-kc/addr_lookup.json` (address `0xfffffe0007ca4040` in `__const`).
- Jump-table dump (KC): `book/dumps/ghidra/out/14.4.1-23E224/kernel-jump-table-dump-kc/jump_tables.json`.
- Pointer window (KC): `book/dumps/ghidra/out/14.4.1-23E224/kernel-pointer-window-kc/pointer_window.json`.
- Pointer window (KC, auto bounds): `book/dumps/ghidra/out/14.4.1-23E224/kernel-pointer-window-kc-auto/pointer_window.json`.

## Evidence & artifacts
- Project: `book/dumps/ghidra/projects/sandbox_14.4.1-23E224`.
- String refs: `book/dumps/ghidra/out/14.4.1-23E224/kernel-string-refs/string_references.json` (190 hits, no externals).
- Import census: `book/dumps/ghidra/out/14.4.1-23E224/kernel-imports/imports_all.json` plus filtered `imports_filtered_sandbox.json` (0 matches for applematch/mac_policy/sandbox/seatbelt).
- Data refs: `book/dumps/ghidra/out/14.4.1-23E224/kernel-data-define/data_refs.json` (sandbox strings + pointer targets, no callers).
- Pointer tables: `book/experiments/kernel-symbols/out/14.4.1-23E224/op_table_candidates.json` (dense tables, unreferenced so far).
