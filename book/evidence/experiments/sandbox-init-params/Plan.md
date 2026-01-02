# Plan – sandbox-init-params

## Canonical entry path
- Binary: `init_params_probe` (to be built in this experiment).
- Profile: inline SBPL string `(version 1)\n(allow default)` passed to `sandbox_init_with_parameters`.
- Invocation (Sonoma 14.4.1, clang): `clang -o sb/build/init_params_probe init_params_probe.c -lsandbox` then `./sb/build/init_params_probe`.
- Entry: `_sandbox_init_with_parameters(profile_str, flags=0, params=NULL, error_out=&err)` in `libsystem_sandbox.dylib`, which dlopens `libsandbox.1.dylib`, resolves `sandbox_compile_string`, and calls `sandbox_apply` → `__sandbox_ms`.

## First trace goal
- Trace this single path userland → `sandbox_init_with_parameters` → `sandbox_compile_string` → `sandbox_apply` → `__sandbox_ms`.
- Capture call graph, handle/parameter layout, and the `(ptr,len)` handoff used for the compiled PolicyGraph blob.

## Steps
- [x] Record call graph for the canonical path (symbols, offsets, argument roles) into `Notes.md` and `out/call_graph.json`.
- [x] Capture handle/parameter struct layout at the compile/apply site; emit `out/layout_snapshot.json`.
- [x] Capture the `__sandbox_ms` handoff (caller, callee, arguments) into `Notes.md` and `out/handoff_snapshot.json`.
- [x] Update `Report.md` with setup, relation to `libsandbox-encoder`, and planned guardrails for this path.
