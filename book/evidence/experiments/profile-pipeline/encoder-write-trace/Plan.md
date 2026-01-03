# Encoder Write Trace – Plan

## Purpose

Trace libsandbox encoder writes during SBPL compilation and join those bytes to
the compiled blob structure. The hook must work even when the write routine is
not exported or dyld-bindable.

## Baseline & scope

- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Inputs: SBPL corpus under `book/tools/sbpl/corpus/`.
- No `sandbox_apply` or runtime probes; compile-only.
- Evidence scope: experiment-local structural join.

## Deliverables

- Compile harness + hook strategies inside this experiment:
  - Triage output (export/bind checks + image base).
  - Callsite reachability classification (exported+bound vs stub vs internal/direct).
  - dyld_info exports/imports presence as alternate evidence when available.
  - Dynamic interpose attempt only when the symbol is exported/bindable.
  - Entry-text patch hook for local symbols (unslid VM addr + runtime slide).
  - UUID gate for unslid addresses and optional `DYLD_SHARED_REGION` overrides.
  - Hardware breakpoint hook (Mach exception port + ARM_DEBUG_STATE64) when patching is blocked.
- Outputs under `out/`:
  - `triage/*.json` (hook triage per input)
  - `traces/*.jsonl` (write records)
  - `blobs/*.sb.bin` (compiled blobs)
  - `manifest.json` (inputs + outputs)
  - `summary.json` (counts + world_id)
  - `trace_analysis.json` (join analysis)
  - `trace_join_check.json` (network-matrix cross-check)
- Experiment-local guardrail scripts (not wired into `book/tests`).

## Steps

1. Build the interposer dylib.
2. Run the harness in triage mode to record export/bind status per input.
3. Use indirect-symbol metadata for libsandbox to decide whether dyld can reach
   the callsite (stub/bind vs internal/direct).
4. If exported/bindable, try dynamic interpose; otherwise compute an address or
   image-relative offset and run patch mode.
5. If patching is blocked by memory protections, use the hardware-breakpoint
   hook (Mach exception port + ARM_DEBUG_STATE64) to trace writes without
   modifying text.
6. Analyze trace-to-blob joins and cross-check with network-matrix diffs.
7. Update `Report.md` and `Notes.md` with results and limitations.
