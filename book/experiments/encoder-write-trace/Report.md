# Encoder Write Trace – Report

## Purpose

Join libsandbox encoder writes to compiled-blob bytes by tracing
`_sb_mutable_buffer_write` during SBPL compilation. This is a static, userland
witness: it does **not** interpret kernel semantics or runtime policy decisions.

## Baseline & scope

- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Inputs: SBPL corpus under `book/tools/sbpl/corpus/`.
- Compile-only: no `sandbox_apply` runs.
- Evidence tier: mapped-but-partial (experiment-local join).

## Deliverables

- Interposer + harness:
  - `harness/sbpl_trace_interpose.c` (DYLD interposer)
  - `harness/build_interposer.sh` (build script)
  - `compile_one.py` / `run_trace.py` (runner)
- Outputs (under `out/`):
  - `traces/*.jsonl` (write records)
  - `blobs/*.sb.bin` (compiled blobs)
  - `manifest.json` (inputs + outputs)
  - `trace_analysis.json` (join analysis)
  - `trace_join_check.json` (network-matrix cross-check)

## Evidence & artifacts

- Interposer build: `book/experiments/encoder-write-trace/out/interposer/sbpl_trace_interpose.dylib`.
- Baseline compile smoke: `book/experiments/encoder-write-trace/out/blobs/_debug.sb.bin`.
- Trace outputs (`out/manifest.json`, `out/traces/*.jsonl`) were not produced because the interposer fails to load (see Status).

## Status

- Status: **blocked**.
- `dyld` aborts when loading the interposer with:\n  `symbol not found in flat namespace '__sb_mutable_buffer_write'`.\n  This indicates `_sb_mutable_buffer_write` is not interposable via the normal\n+  dyld interpose path (local symbol), so the current harness cannot run.

## Running / refreshing

From repo root:

```sh
python3 book/experiments/encoder-write-trace/run_trace.py
python3 book/experiments/encoder-write-trace/analyze_trace.py
python3 book/experiments/encoder-write-trace/check_trace_join.py
```

Note: `run_trace.py` currently aborts at interposer load (dyld symbol lookup
failure). See Status and Blockers.

## Blockers / risks

- `_sb_mutable_buffer_write` is a local symbol in libsandbox on this host; dyld
  interpose cannot resolve it, so the current interposer fails to load.
- Even with a working hook, the cursor parameter may be an offset or a pointer;
  any join must remain explicit about this ambiguity.

## Next steps

- Evaluate an alternate hook strategy that does not rely on dyld interpose for
  local symbols (e.g., runtime patching using image slide + symbol offsets).
- Once a hook works, re-enable the trace pipeline and regenerate the planned
  outputs (`manifest.json`, `trace_analysis.json`, `trace_join_check.json`).
