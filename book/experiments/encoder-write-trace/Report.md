# Encoder Write Trace – Report

## Purpose

Join libsandbox encoder writes to compiled-blob bytes by tracing the internal
write routine during SBPL compilation. This is a static, userland witness: it
does **not** interpret kernel semantics or runtime policy decisions.

## Baseline & scope

- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Inputs: SBPL corpus under `book/tools/sbpl/corpus/`.
- Compile-only: no `sandbox_apply` runs.
- Evidence tier: mapped-but-partial (experiment-local join).

## Deliverables

- Interposer + harness:
  - `harness/sbpl_trace_interpose.c` (triage + hook strategies)
  - Entry-text trampoline patch derived from unslid address + runtime slide
  - `harness/build_interposer.sh` (build script)
  - `compile_one.py` / `run_trace.py` (runner)
- Outputs (under `out/`):
  - `triage/*.json` (hook triage per input)
  - `traces/*.jsonl` (write records)
  - `blobs/*.sb.bin` (compiled blobs)
  - `manifest.json` (inputs + outputs)
  - `summary.json` (counts + world_id)
  - `trace_analysis.json` (join analysis)
  - `trace_join_check.json` (network-matrix cross-check)

## Evidence & artifacts

- Interposer build: `book/experiments/encoder-write-trace/out/interposer/sbpl_trace_interpose.dylib`.
- Baseline compile smoke: `book/experiments/encoder-write-trace/out/blobs/_debug.sb.bin`.
- Trace outputs (`out/manifest.json`, `out/traces/*.jsonl`) have not been produced yet.

## Status

- Status: **blocked**.
- Earlier dyld interpose load failed with `symbol not found in flat namespace '__sb_mutable_buffer_write'`,
  which suggests (but does not prove) the write routine is not exported/bindable.
- The harness now records triage metadata (including callsite reachability) and supports
  dynamic interpose (if exported/bindable) or address-based patching, but no new traces
  have been produced yet.
- A patch-mode viability run computed the runtime address and UUID match but failed to
  patch text pages with `mprotect failed: Permission denied`, yielding zero write hits.
  The patch path now falls back to `mach_vm_protect(..., VM_PROT_COPY)` but still fails
  with `(os/kern) protection failure`; these runs are recorded as hook failures rather
  than generic reachability errors.
- The patcher now uses a W^X-correct flow (RW then RX, no RWX) and records Mach VM
  region metadata. The target region reports `protection: r-x`, `max_protection: r-x`,
  and `max_has_write: false`, which is consistent with an immutable `__TEXT` mapping
  on this host. Patch mode now treats this as a terminal skip (`hook_status:
  skipped_immutable`) rather than attempting to write text pages.

## Running / refreshing

From repo root:

```sh
python3 book/experiments/encoder-write-trace/run_trace.py --mode triage
python3 book/experiments/encoder-write-trace/analyze_trace.py
python3 book/experiments/encoder-write-trace/check_trace_join.py
```

Note: triage mode records hook metadata under `out/triage/`. Traces require
`--mode dynamic` (exported/bindable) or `--mode patch` with a known address/offset.

## Blockers / risks

- We do not yet have triage output confirming export/bind status of the write
  routine. The dyld error is only a hint; the triage output is the witness.
- Dynamic interpose can only affect dyld-bound callsites; direct intra-image
  calls will require patching or an external tracer.
- Address-based patching appears blocked by region max-protection (`r-x` without write)
  even after switching to W^X-correct protection changes. The Mach VM region metadata
  in `out/triage/baseline_allow_all.json` is the current witness.
- Callsite reachability is inferred from the indirect-symbol table (`otool -Iv`)
  on the extracted libsandbox image; this is a partial proxy for dyld bind tables.
- dyld_info exports/imports are recorded as a convenience signal; the extracted
  libsandbox image may fail dyld_info parsing, so a host `/usr/lib` fallback is used.
- `DYLD_SHARED_REGION=private` did not clear the mprotect/VM_PROT_COPY failure;
  `avoid` aborts because core system dylibs are not present on disk when bypassing
  the shared cache.
- Attempting a non-shared-cache helper by loading
  `book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib` via `ctypes.CDLL`
  fails with a code-signature error ("Trying to load an unsigned library").
- A fresh libsandbox extracted with `extract_dsc.swift` (from the dyld shared cache)
  still fails ad-hoc signing (`main executable failed strict validation`), so the
  private-dlopen helper path is currently blocked by code-signature validation.
- DTrace pid-provider probing was attempted but blocked by SIP with "DTrace requires
  additional privileges".
- Even with a working hook, the cursor parameter may be an offset or a pointer;
  any join must remain explicit about this ambiguity.

## Next steps

- Run `run_trace.py --mode triage` to capture export/bind status and callsite
  reachability metadata in `out/triage/`.
- If the symbol is exported/bindable, try `--mode dynamic`; otherwise provide a
  stable address/offset and run `--mode patch`.
- Once a hook works, re-enable the trace pipeline and regenerate the planned
  outputs (`manifest.json`, `trace_analysis.json`, `trace_join_check.json`).
