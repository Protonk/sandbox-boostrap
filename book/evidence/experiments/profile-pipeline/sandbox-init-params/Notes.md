# Notes – sandbox-init-params

## Canonical entry path (init_params_probe)
- Host: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Binary plan: `sb/build/init_params_probe` calling `_sandbox_init_with_parameters("(version 1)\n(allow default)", 0, NULL, &err)`.
- Toolchain/command: `clang -o sb/build/init_params_probe init_params_probe.c -lsandbox` (run from repo root), execute `./sb/build/init_params_probe`.

## Call graph (userland → kernel stub)
- `_sandbox_init_with_parameters` (libsystem_sandbox.dylib @ 0x18b704980):
  - Prologue captures args: x0=profile cstr, x1=flags, x2=params ptr, x3=char** error_out.
  - `dlopen("/usr/lib/libsandbox.1.dylib", RTLD_LAZY|RTLD_LOCAL)` then `dlsym` resolves `sandbox_create_params` / `sandbox_set_param` / `sandbox_free_params` when params are present.
  - Switch table on `flags` picks compile entry (`sandbox_compile_string`/`named`/`file`); callsite for `sandbox_compile_string` via `dlsym` at 0x18b704b44 → `blraaz x8` at 0x18b704b60.
  - After compile returns handle in x0, `dlsym("sandbox_apply")` at 0x18b704b74 → `blraaz x8` at 0x18b704b88 with x0=handle, x1=0 (no container).
  - Error handling runs through `__sandbox_ms` call errors and `asprintf` into error_out when needed.
- `_sandbox_apply` (libsandbox.1.dylib @ 0x183d0985c):
  - x0=profile handle, x1=container path (nullable).
  - Loads handle qword0; if non-zero, stores {qword0, container_ptr} at sp[0],sp[8]; else uses ldp qword1/qword2 from handle+0x8 into sp[0],sp[8] and copies container_ptr to sp[0x10].
  - If container ptr is non-null, `strlen` is used and length is stored at sp[0x10] (or sp[0x18] in the fallback branch); container ptr stays in the arg block.
  - Calls `___sandbox_ms` at 0x183d098e8 with x0="Sandbox", w1=1 when handle qword0 is present, w1=0 otherwise, x2=sp (arg block described above).
- `___sandbox_ms` (libsandbox.1.dylib stub) is the MAC syscall wrapper; no further decoding here.

## Struct layout snapshot (handle consumed by _sandbox_apply)
- Observed from `_sandbox_apply` entry:
  - `handle+0x0` (qword0): when non-zero, becomes first qword in the arg block passed to `__sandbox_ms`. Likely the sb_buffer pointer. Status: partial.
  - `handle+0x8` / `handle+0x10` (qword1/qword2): used as a pair when qword0==0; both copied into the arg block before the container fields. Status: partial.
  - Caller supplies `x1` container path; stored in arg block and optionally measured with `strlen` to emit a length (sp+0x10 or sp+0x18 depending on branch). Status: partial.
- Arg block (sp) passed as x2 to `__sandbox_ms`:
  - `sp+0x0`: buffer handle qword (from handle+0x0 or handle+0x8 depending on branch).
  - `sp+0x8`: second qword (either container ptr or handle qword2 depending on branch).
  - `sp+0x10`: container length when container ptr is non-null in the main branch; in fallback branch, container ptr is placed at sp+0x10 and length (or zero) at sp+0x18.

## Handoff snapshot (sandbox_apply → __sandbox_ms)
- Callsite: `_sandbox_apply` @ 0x183d098e8 (`bl ___sandbox_ms`).
- Arguments:
  - x0: pointer to literal "Sandbox".
  - w1: call code `1` when `handle[0]` is non-zero; `0` when `handle[0]==0` (fallback path).
  - x2: pointer to arg block on stack populated from the handle fields plus container pointer/length as described above.
  - Other registers unchanged; no extra args visible.

## Relation to libsandbox-encoder (baseline)
- Reuses encoder findings: mutable buffer handle at builder+0xe98, `_sb_mutable_buffer_make_immutable` in `_compile` returns sb_buffer* stored at sp+0x60 (see `encoder_sites.json`).
- Current trace shows how that sb_buffer* is packaged into the handle consumed by `_sandbox_apply` and then handed to `__sandbox_ms` via the arg block.

## Run: init_params_probe (host witness)
- Command (repo root): `INIT_PARAMS_PROBE_OUT=book/evidence/experiments/profile-pipeline/sandbox-init-params/out/init_params_probe.sb.bin sb/build/init_params_probe`.
- Output (process-local addresses; JSON in `out/init_params_probe_run.json`):
  - handle words: `[0, 0x127809600, 0x1a0]` (handle[0]==0 triggers fallback branch in `_sandbox_apply`).
  - blob pointer/len inferred: `ptr=0x127809600`, `len=416`; copied to `out/init_params_probe.sb.bin`.
  - arg block to `__sandbox_ms` (w1=0): `{q0=0x127809600, q1=416, q2=0}` (container NULL).
  - `sandbox_apply` return: 0.
- Inspect: `python -m book.api.profile inspect out/init_params_probe.sb.bin --out out/init_params_probe.inspect.json` → length 416, op_entries `[1,1]`, modern-heuristic format.
- Interpretation: the canonical inline profile flows through the handle[0]==0 path, passing (ptr,len) directly in the arg block; matches the fallback branch in `_sandbox_apply`.

## Run: init_params_probe (container variant)
- Command: `INIT_PARAMS_PROBE_CONTAINER=/tmp/init_params_container INIT_PARAMS_PROBE_OUT=.../out/init_params_probe_container.sb.bin INIT_PARAMS_PROBE_RUN_JSON=.../out/init_params_probe_container_run.json sb/build/init_params_probe`.
- Output:
  - handle words: `[0, 0x12f809200, 0x1a0]` (same branch, handle[0]==0).
  - blob pointer/len: `ptr=0x12f809200`, `len=416`; copied to `out/init_params_probe_container.sb.bin` (identical bytes to non-container run; sha256 `19832e...3c92`).
  - arg block (w1=0): `{q0=0x12f809200, q1=416, q2=0}`; container_len=26 ("/tmp/init_params_container").
  - `sandbox_apply` return: 0.

## Run: init_params_probe_forced (handle[0]!=0 path)
- Command: `INIT_PARAMS_FORCE_HANDLE0=1 INIT_PARAMS_PROBE_RUN_ID=init_params_probe_forced INIT_PARAMS_PROBE_OUT=.../out/init_params_probe_forced.sb.bin INIT_PARAMS_PROBE_RUN_JSON=.../out/init_params_probe_forced_run.json sb/build/init_params_probe`.
- Output:
  - handle words presented to `_sandbox_apply`: `[0x16b823470, 0, 0]` (forced copy on stack).
  - blob pointer/len: `ptr=0x149808200`, `len=416` (same bytes/hash as baseline).
  - arg block: `{q0=0x149808200, q1=416, q2=0}`; call_code 1; `sandbox_apply` return: -1 (as expected for synthetic branch coverage).

## Validation snapshot
- `book/tools/sbpl/sandbox_init_params_validate.py` checks all `_run.json` files vs blobs:
  - Ensures blob length matches recorded `blob.len`.
  - Ensures required runs (`init_params_probe`, `init_params_probe_container`) match expected length/hash/call_code for this world_id; writes `out/validation_summary.json` with world_id and per-run metadata.
- Current runs:
  - `init_params_probe`: len 416, call_code 0, sha256 `19832eb9716a32459bee8398c8977fd1dfd575fa26606928f95728462a833c92`.
  - `init_params_probe_container`: same len/hash, call_code 0, container_len 26.
  - `init_params_probe_forced`: len 416, call_code 1, forced branch, blob hash matches baseline.

## Contract
- World-bound invariants: for `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`, the inline profile (with/without container) must yield `blob_len=416`, `blob_sha256=19832e...3c92`, `call_code=0`, and non-zero pointers; guardrail asserts these.
- Pointer addresses are treated as structural (non-zero) not absolute; forced branch is recorded as a variation witness, not a guardrail target.

## Probe interface (env + JSON)
- Env: `INIT_PARAMS_PROBE_MODE` ∈ `{string,named,file,forced}` (default string); `INIT_PARAMS_PROBE_PROFILE` is the profile name for `mode=named`, file path for `mode=file`; `INIT_PARAMS_PROBE_CONTAINER`, `INIT_PARAMS_PROBE_OUT`, `INIT_PARAMS_PROBE_RUN_JSON`, `INIT_PARAMS_PROBE_RUN_ID`, `INIT_PARAMS_FORCE_HANDLE0` (legacy force toggle).
- JSON fields (written via a file opened before `sandbox_apply`): `world_id`, `run_id`, `mode`, `profile`, `profile_id`, `profile_path`, `container`, `container_len`, handle words/hex, `call_code`, `forced_handle0`, `pointer_nonzero`, `blob {ptr_hex,len,file}`, `apply_return`.

## Handle[0] sweep (named/file modes)
- Candidate names recorded at `out/handle_candidate_profiles.json` (63 `.sb` files from `/usr/share/sandbox`, source `usr_share_sandbox`).
- Runs summarized in `out/handle_runs_summary.json`:
  - `init_params_probe` / `init_params_probe_container`: `mode=string`, `handle[0]=0`, `call_code=0`, `blob_len=416`, `sha256=19832e...3c92`, `apply_return=0`.
  - `init_params_probe_forced`: `mode=forced`, `handle[0]=0x16d96f4b0`, `call_code=1`, `blob_len=416`, `sha256=19832e...3c92`, `apply_return=-1` (synthetic variation).
  - `file_simple` (profile `book/evidence/experiments/profile-pipeline/sandbox-init-params/sb/simple_file_profile.sb`): `handle[0]=0`, `call_code=0`, `blob_len=416`, `sha256=19832e...3c92`, `apply_return=0`.
  - `file_ftp_proxy` (profile `/usr/share/sandbox/ftp-proxy.sb`): `handle[0]=0`, `call_code=0`, `blob_len=2612`, `sha256=9255585db74668cd72e7c9ca6aa08fac2dd313d4200de5271f73715246d82ad0`, `apply_return=0`.
  - `named_ftp_proxy`: `handle[0]=0`, `call_code=0`, `blob_len=2612`, `sha256=9255585db74668cd72e7c9ca6aa08fac2dd313d4200de5271f73715246d82ad0`, `apply_return=0`.
  - `named_mDNSResponder`: `handle[0]=0`, `call_code=0`, `blob_len=4492`, `sha256=72c7588bd349c9aff96169a4b7f9676c3558779589833083dc74ca7c0f80bf55`, `apply_return=0`.
  - `named_watool`: `handle[0]=0`, `call_code=0`, `blob_len=2236`, `sha256=6fb785e4aa35946d84624e42fad0dacb392cb3d3eeb2505884c0bdca06440648`, `apply_return=0`.
  - `named_mds`: `mode=named` compile failure (`string-length: argument 1 must be: string`), no run JSON.
- Observation: across named/file sweeps `handle[0]` stayed zero (non-forced); the only non-zero handle[0] remains the synthetic forced branch.
