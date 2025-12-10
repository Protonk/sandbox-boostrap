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
- Command (repo root): `INIT_PARAMS_PROBE_OUT=book/experiments/sandbox-init-params/out/init_params_probe.sb.bin sb/build/init_params_probe`.
- Output (process-local addresses; JSON in `out/init_params_probe_run.json`):
  - handle words: `[0, 0x146809600, 0x1a0]` (handle[0]==0 triggers fallback branch in `_sandbox_apply`).
  - blob pointer/len inferred: `ptr=0x146809600`, `len=416`; copied to `out/init_params_probe.sb.bin`.
  - arg block to `__sandbox_ms` (w1=0): `{q0=0x146809600, q1=416, q2=0}` (container NULL).
  - `sandbox_apply` return: 0.
- Inspect: `python -m book.api.inspect_profile.cli out/init_params_probe.sb.bin --json out/init_params_probe.inspect.json` → length 416, op_entries `[1,1]`, modern-heuristic format.
- Interpretation: the canonical inline profile flows through the handle[0]==0 path, passing (ptr,len) directly in the arg block; matches the fallback branch in `_sandbox_apply`.

## Run: init_params_probe (container variant)
- Command: `INIT_PARAMS_PROBE_CONTAINER=/tmp/init_params_container INIT_PARAMS_PROBE_OUT=.../out/init_params_probe_container.sb.bin INIT_PARAMS_PROBE_RUN_JSON=.../out/init_params_probe_container_run.json sb/build/init_params_probe`.
- Output:
  - handle words: `[0, 0x152009200, 0x1a0]` (same branch, handle[0]==0).
  - blob pointer/len: `ptr=0x152009200`, `len=416`; copied to `out/init_params_probe_container.sb.bin` (identical bytes to non-container run; sha256 `19832e...3c92`).
  - arg block (w1=0): `{q0=0x152009200, q1=416, q2=0}`; container_len=26 ("/tmp/init_params_container").
  - `sandbox_apply` return: 0.

## Validation snapshot
- `validate_runs.py` checks all `_run.json` files vs blobs:
  - Ensures blob length matches recorded `blob.len`.
  - Ensures `call_code` matches `handle_words[0]!=0`.
  - Emits `out/validation_summary.json` with length/call_code/sha256 per run.
- Current runs:
  - `init_params_probe`: len 416, call_code 0, sha256 `19832eb9716a32459bee8398c8977fd1dfd575fa26606928f95728462a833c92`.
  - `init_params_probe_container`: same len/hash, call_code 0.
