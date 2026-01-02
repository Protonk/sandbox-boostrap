# Encoder Write Trace – Report

## Purpose

Join libsandbox encoder writes to compiled-blob bytes by tracing the internal
write routine during SBPL compilation. This is a static, userland witness: it
does **not** interpret kernel semantics or runtime policy decisions.

## Baseline & scope

- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Inputs: SBPL corpus under `book/tools/sbpl/corpus/`.
- Compile-only: no `sandbox_apply` runs.
- Evidence tier: mapped (experiment-local join).

## Deliverables

- Interposer + harness:
  - `harness/sbpl_trace_interpose.c` (triage + hook strategies)
  - Entry-text trampoline patch derived from unslid address + runtime slide
  - `harness/build_interposer.sh` (build script)
  - `harness/mach_exc_server.c` / `harness/mach_exc_server.h` (MIG server stubs)
  - `harness/mach_exc_user.c` / `harness/mach_exc_user.h` (exception forwarding stubs)
  - `run_trace.py` (runner; compile subprocess uses `book.api.profile.compile`)
  - `book/tools/sbpl/encoder_write_trace_analyze.py` (join analysis)
  - `book/tools/sbpl/encoder_write_trace_check.py` (join guardrail)
- Outputs (under `out/`):
  - `triage/*.json` (hook triage per input)
  - `stats/*.stats.json` (hardware-breakpoint counters)
  - `traces/*.jsonl` (write records)
  - `blobs/*.sb.bin` (compiled blobs)
  - `manifest.json` (inputs + outputs)
  - `summary.json` (counts + world_id)
  - `trace_analysis.json` (join analysis)
  - `trace_join_check.json` (network-matrix cross-check)

## Evidence & artifacts

- Interposer build: `book/evidence/experiments/profile-pipeline/encoder-write-trace/out/interposer/sbpl_trace_interpose.dylib`.
- Baseline compile smoke: `book/evidence/experiments/profile-pipeline/encoder-write-trace/out/blobs/_debug.sb.bin`.
- Trace outputs: `book/evidence/experiments/profile-pipeline/encoder-write-trace/out/traces/baseline_allow_all.jsonl` (hardware-breakpoint run).
- Stats outputs: `book/evidence/experiments/profile-pipeline/encoder-write-trace/out/stats/*.stats.json`.
- Join analysis: `book/evidence/experiments/profile-pipeline/encoder-write-trace/out/trace_analysis.json`.
- Join cross-check: `book/evidence/experiments/profile-pipeline/encoder-write-trace/out/trace_join_check.json`.

## Status

- Status: **partial**.
- Earlier dyld interpose load failed with `symbol not found in flat namespace '__sb_mutable_buffer_write'`,
  which suggests (but does not prove) the write routine is not exported/bindable.
- The harness records triage metadata (including callsite reachability) and supports
  dynamic interpose (if exported/bindable), address-based patching, or hardware-breakpoint
  tracing for internal callsites.
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
- A hardware-breakpoint hook (Mach exception port + ARM_DEBUG_STATE64) now produces
  write records without modifying text. The baseline run (`baseline_allow_all`) yields
  307 write records in `book/evidence/experiments/profile-pipeline/encoder-write-trace/out/traces/baseline_allow_all.jsonl`
  with `hook_status: ok` in `book/evidence/experiments/profile-pipeline/encoder-write-trace/out/triage/baseline_allow_all.json`.
- Routing is task‑level (`task_swap_exception_ports`) with proactive per‑thread
  breakpoint arming. Exception handling now treats `EXC_BREAKPOINT` events as
  break vs step based on per‑thread `step_active` state (code/subcode gating
  proved unstable on this host), with forwarding reserved for non‑breakpoint
  exceptions.
- Added a secondary hardware breakpoint on `_sb_mutable_buffer_make_immutable`
  to record immutable buffer pointers in stats; the pointer does not currently
  align with write-event buffer addresses, so join selection still relies on
  per-buffer trace alignment.
- `run_trace.py` now retries the compile subprocess on SIGSEGV/SIGTRAP by
  default and records compile attempts/signals in triage and the manifest
  instead of aborting the run.
- `trace_analysis.json` aligns gapped coverage to the blob window (`base_offset: 0`,
  `window_len: 416`) and marks `witnessed_ranges` vs `hole_ranges` (currently a
  6‑byte hole at `[394,400)`).
- `trace_join_check.json` now checks at least three network-matrix pairs
  (`domain_af_inet_vs_af_system`, `type_sock_stream_vs_sock_dgram`,
  `proto_tcp_vs_udp`) using the
  gapped alignment window when it offers wider coverage than the best subset
  match; both pairs report witnessed coverage at offset 410 with a traced window
  `[0, 484)` and a 6‑byte hole at `[394,400)`.
- The runner now supports compile‑string inputs plus params handles. Compiling
  `param_path.sb` without params fails in both file and string modes with
  `compile failed: invalid data type of path filter; expected pattern, got boolean`,
  while providing `{"ROOT": "/private/tmp"}` succeeds in both modes. Under
  `hw_breakpoint`, the error cases still emit some write records before the
  failure (file/string: 16), and the successful file/string runs emit
  similar write counts (204 vs 206) with the same `[394,400)` hole. Using
  `{"ROOT": "/private/var/tmp"}` increases the aligned window length to 511
  with the same hole.
- File vs string compile for `allow_all` produces identical windows (`[0,416)`
  with a `[394,400)` hole). An unused params map (`{"UNUSED":"1"}`) preserves
  the window but yields fewer write records (193 vs 214).
- `pair_dt_all_inet_stream` and `golden_strict_1` produce small reconstructed
  spans (21 and 22 bytes respectively) without gapped alignment; file vs string
  differ only in record counts. `gate_airlock_minimal` yields a larger window
  (513) with a `[396,400)` hole in both file and string modes.

## Running / refreshing

From repo root:

```sh
python3 book/evidence/experiments/profile-pipeline/encoder-write-trace/run_trace.py --mode triage
python3 book/tools/sbpl/encoder_write_trace_analyze.py
python3 book/tools/sbpl/encoder_write_trace_check.py
```

Note: triage mode records hook metadata under `out/triage/`. Traces require
`--mode dynamic` (exported/bindable), `--mode patch` with a known address/offset,
or `--mode hw_breakpoint` when patching is blocked by region max-protection.
Use `--retries 0` to disable compile retries if you want a single attempt.
For compile‑string/params checks (and other compile‑flavor probes), run:
`python3 book/evidence/experiments/profile-pipeline/encoder-write-trace/run_trace.py --inputs book/evidence/experiments/profile-pipeline/encoder-write-trace/inputs_params.json --mode triage`.
For the hardware‑breakpoint comparison, rerun with `--mode hw_breakpoint` and
then `book/tools/sbpl/encoder_write_trace_analyze.py`.

## Blockers / risks

- We do not yet have triage output confirming export/bind status of the write
  routine. The dyld error is only a hint; the triage output is the witness.
- Dynamic interpose can only affect dyld-bound callsites; direct intra-image
  calls will require patching or an external tracer.
- Address-based patching appears blocked by region max-protection (`r-x` without write)
  even after switching to W^X-correct protection changes. The Mach VM region metadata
  in `out/triage/baseline_allow_all.json` is the current witness.
- The hardware-breakpoint hook currently arms the current thread; if compilation
  migrates to other threads, additional thread coverage may be required.
- The breakpoint handler relies on Mach exception codes to distinguish break
  vs step; the current implementation instead uses per‑thread `step_active`,
  which may mis-handle unrelated breakpoints in-process.
- Compile subprocesses can still crash under hardware-breakpoint tracing; these
  failures are now recorded (attempts/signals) but do not block analysis.
- Hardware-breakpoint trace records include `reported_len` and `chunk_offset`
  when chunking is required, and triage records ring drops and truncated
  captures to make loss explicit.
- Callsite reachability is inferred from the indirect-symbol table (`otool -Iv`)
  on the extracted libsandbox image; this is a partial proxy for dyld bind tables.
- dyld_info exports/imports are recorded as a convenience signal; the extracted
  libsandbox image may fail dyld_info parsing, so a host `/usr/lib` fallback is used.
- `DYLD_SHARED_REGION=private` did not clear the mprotect/VM_PROT_COPY failure;
  `avoid` aborts because core system dylibs are not present on disk when bypassing
  the shared cache.
- Attempting a non-shared-cache helper by loading
  `book/evidence/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib` via `ctypes.CDLL`
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
- Once more inputs are traced, rerun `book/tools/sbpl/encoder_write_trace_analyze.py` and `book/tools/sbpl/encoder_write_trace_check.py`
  to extend join coverage beyond the baseline manifest.
