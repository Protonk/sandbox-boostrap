# Experiment: sandbox-init-params

## AIM (initial)

Understand how `libsystem_sandbox` and related userland entry points (e.g., `sandbox_init`, `sandbox_init_with_parameters`, `sandbox_apply`) on Sonoma 14.4.1:
- Resolve and call the libsandbox compile entry points (`sandbox_compile_*`),
- Represent compiled profiles and parameters as handles/structures, and
- Hand compiled profiles and parameters to `__sandbox_ms`.

This experiment starts where `libsandbox-encoder` stopped: it treats the compiled `sb_buffer*` from libsandbox as a black-box “profile handle” and focuses on the `sandbox-init` / parameter plumbing and syscall argument packing.

## Relationship to libsandbox-encoder

- Depends on the closed experiment at `book/experiments/libsandbox-encoder/` for:
  - The definition of the compiled profile blob and its PolicyGraph layout.
  - The identification of encoder sites in `libsandbox.1.dylib` (`_emit_*`, `_record_condition_data`, `_compile`, builder+0xe98).
- Does **not** redo PolicyGraph decoding or field2 layout; those results are assumed as given.

## Setup (canonical path for this iteration)
- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`, Apple Silicon, SIP enabled.
- Binary plan: `sb/build/init_params_probe` (to be built in this experiment).
  - Source intent: call `_sandbox_init_with_parameters("(version 1)\n(allow default)", 0, NULL, &err)`.
  - Build/Run (from repo root): `clang -o sb/build/init_params_probe init_params_probe.c -lsandbox` then `./sb/build/init_params_probe`.
- Entry path: `_sandbox_init_with_parameters` in `libsystem_sandbox.dylib` → dlopen `/usr/lib/libsandbox.1.dylib` → `sandbox_compile_string` → `sandbox_apply` → `__sandbox_ms`.

## Relation to libsandbox-encoder

- Shared inputs: `book/experiments/libsandbox-encoder/out/encoder_sites.json` (mutable buffer at builder+0xe98, `_sb_mutable_buffer_make_immutable` at 0x183ced36c returning sb_buffer*), `tag_layout_overrides.json` (tag layouts).
- This experiment anchors the caller side: how `_sandbox_init_with_parameters` resolves compile/apply symbols, how `_sandbox_apply` packages the sb_buffer handle, and how that handle is handed to `__sandbox_ms`.
- The sb_buffer ptr produced by `_sb_mutable_buffer_make_immutable` is expected to flow into the handle consumed by `_sandbox_apply`; the current trace records where that handle is read and how it is passed to the MAC syscall stub.

## Status (first concrete trace)
- Call graph captured for the canonical path: `_sandbox_init_with_parameters` (0x18b704980) → dynamic `sandbox_compile_string` → dynamic `sandbox_apply` → `_sandbox_apply` (0x183d0985c) → `___sandbox_ms` callsite (0x183d098e8).
- Struct snapshot: `_sandbox_apply` treats the compiled profile handle as a small struct:
  - `handle[0]` qword: when non-zero, copied directly into the arg block passed to `__sandbox_ms` (likely sb_buffer*).
  - `handle[1]/handle[2]` qwords: used when `handle[0]==0`, copied as a pair into the arg block.
  - Caller-supplied container pointer/length are appended in the arg block; `strlen` computes length when the pointer is non-null.
- Handoff snapshot: `__sandbox_ms` receives x0="Sandbox", w1=1 when `handle[0]!=0` (else 0), x2=arg block built from the handle and optional container. Arg block layout and call graph recorded in `out/`.
- Host witness run (`init_params_probe`):
  - Profile `(version 1)\n(allow default)` compiled via `sandbox_compile_string` → handle words `[0, 0x146809600, 0x1a0]` (process-local; handle[0]==0 branch).
  - Arg block to `__sandbox_ms` (call_code w1=0): `{q0=0x146809600, q1=416, q2=0}`; `sandbox_apply` returned 0.
  - Compiled blob captured at `out/init_params_probe.sb.bin` (416 bytes), inspected via `book.api.inspect_profile.cli` → format `modern-heuristic`, op_entries `[1,1]`.
- Container variant (`INIT_PARAMS_PROBE_CONTAINER=/tmp/init_params_container`):
  - Handle words `[0, 0x152009200, 0x1a0]`, call_code 0 (same branch).
  - Arg block `{q0=0x152009200, q1=416, q2=0}`, container_len 26, `sandbox_apply` returned 0.
  - Blob identical to baseline (sha256 `19832eb9716a32459bee8398c8977fd1dfd575fa26606928f95728462a833c92`).
- Validation: `validate_runs.py` (added) recomputes length/call_code/sha256 for all runs and writes `out/validation_summary.json`; current runs both len 416, call_code 0, sha256 `19832e...3c92`.
- Artifacts emitted:
  - `Plan.md` (canonical scenario and steps).
  - `Notes.md` (call graph, layout snapshot, handoff snapshot, run log).
  - `out/call_graph.json`, `out/layout_snapshot.json`, `out/handoff_snapshot.json`, `out/init_params_probe*.sb.bin`, `out/init_params_probe*.inspect.json`, `out/init_params_probe*_run.json`, `out/validation_summary.json`, `validate_runs.py`.

## Planned guardrails (not yet implemented)
- For `init_params_probe`, the `(ptr,len)` passed to `__sandbox_ms` should match the sb_buffer produced by `sandbox_compile_string` for the inline profile.
- Argument ordering/field offsets for the handle consumed by `_sandbox_apply` should match the recorded `layout_snapshot.json` for this world.
- The call graph (symbols and key callsites) should remain stable for this world_id; deviations should trigger a rerun/refresh of the witness JSONs.
