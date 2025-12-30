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

## Probe interface (world-bound)
- Env vars:
  - `INIT_PARAMS_PROBE_MODE` ∈ `{string,named,file,forced}` (default `string`); `forced` flips to the branch where `_sandbox_apply` sees `handle[0]!=0`.
  - `INIT_PARAMS_PROBE_PROFILE`: profile name for `mode=named`, file path (absolute) for `mode=file`, ignored otherwise.
  - `INIT_PARAMS_PROBE_CONTAINER`, `INIT_PARAMS_PROBE_OUT`, `INIT_PARAMS_PROBE_RUN_JSON`, `INIT_PARAMS_PROBE_RUN_ID`, `INIT_PARAMS_FORCE_HANDLE0` (legacy force toggle).
- JSON fields (world_id-bound schema, emitted even under restrictive profiles by opening the file before `sandbox_apply`):
  - `world_id`, `run_id`, `mode`, `profile`, `profile_id`, `profile_path`, `container`, `container_len`.
  - Handle and handoff: `handle_ptr_hex`, `handle_words`, `handle_words_hex`, `call_code`, `forced_handle0`, `pointer_nonzero`, `blob {ptr_hex,len,file}`, `apply_return`.

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
  - Profile `(version 1)\n(allow default)` compiled via `sandbox_compile_string` → handle words `[0, 0x127809600, 0x1a0]` (process-local; handle[0]==0 branch).
  - Arg block to `__sandbox_ms` (call_code w1=0): `{q0=0x127809600, q1=416, q2=0}`; `sandbox_apply` returned 0.
  - Compiled blob captured at `out/init_params_probe.sb.bin` (416 bytes), inspected via `book.api.profile inspect` → format `modern-heuristic`, op_entries `[1,1]`.
- Container variant (`INIT_PARAMS_PROBE_CONTAINER=/tmp/init_params_container`):
  - Handle words `[0, 0x12f809200, 0x1a0]`, call_code 0 (same branch).
  - Arg block `{q0=0x12f809200, q1=416, q2=0}`, container_len 26, `sandbox_apply` returned 0.
  - Blob identical to baseline (sha256 `19832eb9716a32459bee8398c8977fd1dfd575fa26606928f95728462a833c92`).
- Forced branch witness (`INIT_PARAMS_PROBE_MODE=forced`, default run_id `init_params_probe_forced`):
  - Applies via a local packed handle so `handle[0]!=0`, call_code 1, arg block `{q0=0x149808200, q1=416, q2=0}`, `sandbox_apply` returned -1. Blob still matches baseline hash/len.
- Validation: `validate_runs.py` recomputes length/call_code/sha256 for all runs and writes `out/validation_summary.json`; current required runs are len 416, call_code 0, sha256 `19832e...3c92`.
- Artifacts emitted:
  - `Plan.md` (canonical scenario and steps).
  - `Notes.md` (call graph, layout snapshot, handoff snapshot, run log).
  - `out/call_graph.json`, `out/layout_snapshot.json`, `out/handoff_snapshot.json`, `out/init_params_probe*.sb.bin`, `out/init_params_probe*.inspect.json`, `out/init_params_probe*_run.json`, `out/validation_summary.json`, `out/handle_candidate_profiles.json`, `out/handle_runs_summary.json`, `validate_runs.py`.

## Handle[0] harvesting (named/file variants)
- Candidate set recorded at `out/handle_candidate_profiles.json` (63 `.sb` names from `/usr/share/sandbox`, source `usr_share_sandbox`).
- Runs exercised via the extended probe interface (all `world_id` bound, see `out/handle_runs_summary.json` for machine-readable data):
  - `mode=string` and `mode=string`+container: `call_code=0`, `blob_len=416`, sha256 `19832e...3c92`, `handle[0]=0`.
  - `mode=forced` (branch coverage only): `call_code=1`, `handle[0]!=0`, blob matches baseline hash/len, apply_return -1.
  - `mode=file` simple inline (`sb/simple_file_profile.sb`) and `/usr/share/sandbox/ftp-proxy.sb`: `handle[0]=0`, `call_code=0`, blob lens 416 and 2612 respectively.
  - `mode=named` (`ftp-proxy`, `mDNSResponder`, `watool`): `handle[0]=0`, `call_code=0`, blob lens 2612/4492/2236, hashes recorded in summary.
  - Attempted `mode=named profile=mds` failed at compile time (`string-length: argument 1 must be: string`); no run JSON produced.
- Result: no natural `handle[0]!=0` witness yet for this world; the forced branch remains the only non-zero handle[0] path and is treated as a variation witness, not part of the guardrail contract.

## Contract for this world_id
- For `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`, running `init_params_probe` (with/without container) must produce a compiled blob of length 416 and sha256 `19832eb9716a32459bee8398c8977fd1dfd575fa26606928f95728462a833c92`, with `call_code` = 0.
- Pointer values are treated as structural (non-zero) but not fixed; guardrail asserts length/hash/call_code only.
- Validation/guardrail: `book/graph/concepts/validation/sandbox_init_params_job.py` reads `out/validation_summary.json`, checks required runs for this world, and is exercised by `book/tests/planes/contracts/test_sandbox_init_params_guardrail.py`. Additional named/file runs are recorded as variation witnesses only.

## Planned guardrails (not yet implemented)
- For `init_params_probe`, the `(ptr,len)` passed to `__sandbox_ms` should match the sb_buffer produced by `sandbox_compile_string` for the inline profile.
- Argument ordering/field offsets for the handle consumed by `_sandbox_apply` should match the recorded `layout_snapshot.json` for this world.
- The call graph (symbols and key callsites) should remain stable for this world_id; deviations should trigger a rerun/refresh of the witness JSONs.
