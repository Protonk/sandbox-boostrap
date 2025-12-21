# Encoder Write Trace – Plan

## Purpose

Trace userland `_sb_mutable_buffer_write` emissions during SBPL compilation and
join those bytes to the compiled blob structure. This experiment is static-only
and does **not** interpret kernel semantics or runtime policy.

## Baseline & scope

- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Inputs: SBPL corpus under `book/tools/sbpl/corpus/`.
- No `sandbox_apply` or runtime probes; compile-only.
- Evidence tier: mapped-but-partial (experiment-local structural join).

## Deliverables

- Compile harness + interposer inside this experiment:
  - C interposer for `_sb_mutable_buffer_write`.
  - Runner that compiles SBPL under the interposer and writes trace logs.
- Outputs under `out/`:
  - `traces/*.jsonl` (write records)
  - `blobs/*.sb.bin` (compiled blobs)
  - `manifest.json` (inputs + outputs)
  - `trace_analysis.json` (join analysis)
  - `trace_join_check.json` (network-matrix cross-check)
- Experiment-local guardrail scripts (not wired into `book/tests`).

## Steps

1. Build the interposer dylib.
2. Run the trace harness on the curated input subset.
3. Analyze trace-to-blob joins and cross-check with network-matrix diffs.
4. Update `Report.md` and `Notes.md` with results and limitations.
