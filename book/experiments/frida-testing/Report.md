# frida-testing

## Purpose
Explore whether Frida-based instrumentation can provide host-bound runtime witnesses for sandbox behavior on the Sonoma 14.4.1 baseline. This experiment is exploratory; there is no host witness yet, and no claims are promoted beyond substrate theory.

## Baseline & scope
- world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)
- Scope: Frida tooling, minimal probes, and runtime logs captured under this experiment.
- Out of scope: cross-version behavior, new vocabulary names, and promotion to mappings/CARTON without validation outputs.

## Deliverables / expected outcomes
- Bootstrap assets: target binary, Frida hooks, and a Python runner using the Frida API.
- Runtime logs or traces in `book/experiments/frida-testing/out/`, with repo-relative paths.
- Notes entries documenting runs, including failures or apply-stage gates.

## Plan & execution log
- Planned: verify the Frida CLI and Python bindings used by this repo's venv.
- Planned: define a minimal probe target and capture a first trace/log.
- Planned: map any observations to existing operations/filters or record as "we don't know yet".
- Planned: attach-first smoke witness using EntitlementJail; treat spawn as unstable on this host.
- Completed: added a minimal target, hook scripts, and a Python runner.
- Completed: attach-first plumbing witnesses against `open_loop` (smoke, export inventory, fs_open errno events).
- Attempted: spawn-based fs_open and sandbox export runs (terminated before emitting events).
- Attempted: attach-first smoke run against EntitlementJail CLI (runner exception; helper + target crashed).
- Attempted: attach-first smoke run against EntitlementJail `ProbeService_debuggable` XPC target (runner exception; target killed with code-signing invalid page).
- Completed: attach-first smoke run against EntitlementJail `ProbeService_fully_injectable` XPC target using `run-xpc --hold-open`.
- Completed: export inventory against `ProbeService_fully_injectable` (libsystem_sandbox.dylib export list).
- Attempted: fs_open against `ProbeService_fully_injectable`; hook installed but no fs-open events (fs_op executed in a different PID).
- Attempted: attach-first smoke run against `ProbeService_debuggable` with `--hold-open` (runner exception; target killed with code-signing invalid page).
- Completed: fs_open self-open witness inside `ProbeService_fully_injectable` using `fs_open_selftest.js` (errno event observed).
- Completed: extracted Frida runner core into `book/api/frida/runner.py` and kept `book/experiments/frida-testing/run_frida.py` as a CLI wrapper.
- Completed: expanded fs_open hook coverage to include open/openat $NOCANCEL and __open* variants.
- Completed: added `interceptor_selftest.js` and `fs_open_funnel.js` to validate Interceptor and discover open-call paths.
- Attempted: initial Interceptor selftest run failed due to a missing `Process.enumerateEnvironment` API.
- Completed: Interceptor selftest on `ProbeService_fully_injectable` confirmed hook firing and errno capture.
- Completed: added `sandbox_trace.js` and `parse_sandbox_trace.py` for sandbox trace gating.
- Attempted: sandbox trace hook initial run failed due to missing `Module.findExportByName`.
- Completed: sandbox trace hook runs but reports `sandbox_set_trace_path` missing in `libsystem_sandbox.dylib` for `ProbeService_fully_injectable` (no trace file).
- Completed: expanded file-decision funnel (metadata/xattr/open) and observed `__open` + `open` errno hits during fs_op.

## Evidence & artifacts
- Bootstrap target: `book/experiments/frida-testing/targets/open_loop.c`.
- Bootstrap binary: `book/experiments/frida-testing/targets/open_loop`.
- Hooks: `book/experiments/frida-testing/hooks/fs_open.js`, `book/experiments/frida-testing/hooks/fs_open_selftest.js`, `book/experiments/frida-testing/hooks/fs_open_funnel.js`, `book/experiments/frida-testing/hooks/interceptor_selftest.js`, `book/experiments/frida-testing/hooks/sandbox_trace.js`, and `book/experiments/frida-testing/hooks/discover_sandbox_exports.js`.
- Smoke hook: `book/experiments/frida-testing/hooks/smoke.js`.
- Runner: `book/api/frida/runner.py` (core) and `book/experiments/frida-testing/run_frida.py` (CLI wrapper).
- Trace parser: `book/experiments/frida-testing/parse_sandbox_trace.py`.

- Attach-first plumbing witness (baseline target `open_loop`):
  - Run `book/experiments/frida-testing/out/0bd798d6-5986-4a26-a19c-28f7d577f240` (smoke): script sha256 `d8711d9b959eb7a6275892f43b9130f3c825cbd15d8c0313fdc4a1a0e989b150`, event kinds `{"runner-start":1,"stage":4,"smoke":1,"session-detached":1}`.
  - Run `book/experiments/frida-testing/out/903d8465-79c3-4ddf-ab01-83892c4a409c` (discover_sandbox_exports): script sha256 `7051d15476ac8e44336368b57daf858a55f8cb13e923ff819b4dc0371f2826ce`, event kinds `{"runner-start":1,"stage":4,"exports":1,"session-detached":1}`.
    - Export payload: module `libsystem_sandbox.dylib`, count `87`, first 10 names: `sandbox_builtin_query`, `sandbox_check`, `sandbox_check_bulk`, `sandbox_check_by_audit_token`, `sandbox_check_by_reference`, `sandbox_check_by_uniqueid`, `sandbox_check_message_filter_integer`, `sandbox_check_message_filter_string`, `sandbox_check_process_signal_target`, `sandbox_check_protected_app_container`.
  - Run `book/experiments/frida-testing/out/4f161bec-6ef0-4614-b070-58e9596f03a2` (fs_open): script sha256 `724999594e57ad1c0ef73405ab1935bbb2ebe1c0b98adde90f824c2915c0372c`, event kinds `{"runner-start":1,"stage":4,"hook-installed":3,"fs-open":10,"session-detached":1}`; errno histogram `{"13":10}` using the deterministic deny path `/tmp/frida_testing_noaccess`.

- Earlier failures (pre-plumbing):
- Run `book/experiments/frida-testing/out/04968c5a-ab8b-45d9-8d41-84f11f223d64` (fs_open): script sha256 `666ea5243d87d008b41e5a444ae30f8cbced3802462ae659dc66db02659ab135`, event kinds `{}` (events.jsonl empty).
- Run `book/experiments/frida-testing/out/64dfc33f-3275-4656-94c3-a427dd129a95` (discover_sandbox_exports): script sha256 `7051d15476ac8e44336368b57daf858a55f8cb13e923ff819b4dc0371f2826ce`, event kinds `{}` (events.jsonl empty).
- Run `book/experiments/frida-testing/out/5b0825cf-b3be-4a24-9a98-37fd4da5cb2f` (smoke attach to EntitlementJail CLI): script sha256 `d8711d9b959eb7a6275892f43b9130f3c825cbd15d8c0313fdc4a1a0e989b150`, event kinds `{\"runner-exception\": 1}`.

## EntitlementJail runs
- Run `book/experiments/frida-testing/out/6bf9e68e-1984-410d-9c9d-bc7b4a0023b8` (smoke attach to EntitlementJail `ProbeService_debuggable`): script sha256 `d8711d9b959eb7a6275892f43b9130f3c825cbd15d8c0313fdc4a1a0e989b150`, runner kinds `{\"runner-start\":1,\"stage\":2,\"runner-exception\":1}`.
- Run `book/experiments/frida-testing/out/fadc03b3-eaf8-4b4c-a8e0-176f476a31ce` (smoke attach to EntitlementJail `ProbeService_debuggable` with `--hold-open`): script sha256 `d8711d9b959eb7a6275892f43b9130f3c825cbd15d8c0313fdc4a1a0e989b150`, runner kinds `{\"runner-start\":1,\"stage\":2,\"runner-exception\":1}`.
- Run `book/experiments/frida-testing/out/539ea0e4-fd01-4b23-b698-17e5256afc3f` (smoke attach to EntitlementJail `ProbeService_fully_injectable`): script sha256 `d8711d9b959eb7a6275892f43b9130f3c825cbd15d8c0313fdc4a1a0e989b150`, event kinds `{\"runner-start\":1,\"stage\":4,\"smoke\":1,\"session-detached\":1}`.
- Run `book/experiments/frida-testing/out/9fc56e61-bd29-4e04-b2a8-c3497114d624` (discover_sandbox_exports on `ProbeService_fully_injectable`): script sha256 `7051d15476ac8e44336368b57daf858a55f8cb13e923ff819b4dc0371f2826ce`, event kinds `{\"runner-start\":1,\"stage\":4,\"exports\":1,\"session-detached\":1}`.
  - Export payload: module `libsystem_sandbox.dylib`, count `87`, first 10 names: `sandbox_builtin_query`, `sandbox_check`, `sandbox_check_bulk`, `sandbox_check_by_audit_token`, `sandbox_check_by_reference`, `sandbox_check_by_uniqueid`, `sandbox_check_message_filter_integer`, `sandbox_check_message_filter_string`, `sandbox_check_process_signal_target`, `sandbox_check_protected_app_container`.
- Run `book/experiments/frida-testing/out/c014afa1-e042-4373-a69a-510be8632aca` (fs_open attach to `ProbeService_fully_injectable`): script sha256 `724999594e57ad1c0ef73405ab1935bbb2ebe1c0b98adde90f824c2915c0372c`, event kinds `{\"runner-start\":1,\"stage\":4,\"hook-installed\":3,\"session-detached\":1}`; no `fs-open` events observed.
- Run `book/experiments/frida-testing/out/6d8f44e4-1fa0-4f99-bab6-bb13f6858257` (smoke attach to EntitlementJail `ProbeService_fully_injectable`): script sha256 `d8711d9b959eb7a6275892f43b9130f3c825cbd15d8c0313fdc4a1a0e989b150`, event kinds `{\"runner-start\":1,\"stage\":4,\"smoke\":1,\"session-detached\":1}`.
- Run `book/experiments/frida-testing/out/673e5a1e-1fab-4010-a74e-9a91b217f830` (discover_sandbox_exports on `ProbeService_fully_injectable`): script sha256 `7051d15476ac8e44336368b57daf858a55f8cb13e923ff819b4dc0371f2826ce`, event kinds `{\"runner-start\":1,\"stage\":4,\"exports\":1,\"session-detached\":1}`.
  - Export payload: module `libsystem_sandbox.dylib`, count `87`, first 10 names: `sandbox_builtin_query`, `sandbox_check`, `sandbox_check_bulk`, `sandbox_check_by_audit_token`, `sandbox_check_by_reference`, `sandbox_check_by_uniqueid`, `sandbox_check_message_filter_integer`, `sandbox_check_message_filter_string`, `sandbox_check_process_signal_target`, `sandbox_check_protected_app_container`.
- Run `book/experiments/frida-testing/out/56577123-16b4-4335-be63-3478e63a7c88` (fs_open self-open on `ProbeService_fully_injectable`): script sha256 `151ffdc95b52c5afbb92263537a761643d24522815e15804a726ec73fef02e52`, event kinds `{\"runner-start\":1,\"stage\":4,\"hook-installed\":3,\"self-open\":1,\"fs-open\":1,\"session-detached\":1}`; errno histogram `{\"13\":1}` for the service container tmp path `ej_noaccess`.
- Run `book/experiments/frida-testing/out/cb34ec8c-6798-4811-9793-9b4c99efe912` (attach wait + fs_op on `ProbeService_fully_injectable`): script sha256 `724999594e57ad1c0ef73405ab1935bbb2ebe1c0b98adde90f824c2915c0372c`, runner kinds `{\"runner-start\":1,\"stage\":4,\"session-detached\":1}`, send kinds `{\"hook-installed\":3}`; wait metadata recorded in the `run-xpc` JSON output (normalized_outcome ok).
- Run `book/experiments/frida-testing/out/690fb15e-6664-48eb-8031-54d6068f3206` (attach wait + fs_op direct-path on `ProbeService_fully_injectable`): script sha256 `724999594e57ad1c0ef73405ab1935bbb2ebe1c0b98adde90f824c2915c0372c`, runner kinds `{\"runner-start\":1,\"stage\":4,\"session-detached\":1}`, send kinds `{\"hook-installed\":3}`; fs_op returned errno 13 (permission_error) in `run-xpc` output.
- Run `book/experiments/frida-testing/out/bb6437a1-e7d8-4734-a4ee-a857b3762208` (attach wait + fs_op direct-path on `ProbeService_fully_injectable` with expanded hook coverage): script sha256 `b6e605a6a7624d32ba86d16dac9071c02585273fbce502a5c26354459ca50352`, runner kinds `{\"runner-start\":1,\"stage\":4,\"session-detached\":1}`, send kinds `{\"hook-installed\":9}`; fs_op returned errno 13 (permission_error) in `run-xpc` output.
- Run `book/experiments/frida-testing/out/9bf3d548-783e-4d67-9ded-0699d2ec4050` (interceptor_selftest initial attempt on `ProbeService_fully_injectable`): script sha256 `53b9b9a8a80dcc66bf9f261954c16f70cfd92135be950fb4f9be80d43edd861b`, event kinds `{\"runner-start\":1,\"stage\":4,\"error\":1,\"session-detached\":1}`; error `TypeError: not a function` from `Process.enumerateEnvironment`.
- Run `book/experiments/frida-testing/out/cdbf72da-d118-4875-babb-1498bc770e4a` (interceptor_selftest on `ProbeService_fully_injectable`): script sha256 `6a6b574339e2beafa77dc544b6c4ebc8a394951ac42b2c0264b2751be9e3e951`, event kinds `{\"runner-start\":1,\"stage\":4,\"interceptor-selftest\":3,\"session-detached\":1}`; hook fired on `open` with errno 2 for `/tmp/frida_testing_noaccess`.
- Run `book/experiments/frida-testing/out/c5b2484c-3e8d-4f26-9074-f59742f45e20` (fs_open_funnel on `ProbeService_fully_injectable`): script sha256 `8516afb5331a9794b4737a4ea588e8d5774ed1af576c29dd924251d0de21d808`, event kinds `{\"runner-start\":1,\"stage\":4,\"funnel-candidates\":1,\"funnel-hook\":16,\"session-detached\":1}`; candidates include `__open*`, `open*`, and `guarded_open_dprotected_np`; no `funnel-hit` events observed.
- Run `book/experiments/frida-testing/out/75b513c6-b674-4a04-8988-3cdc87874958` (fs_open_funnel with syscall hooks on `ProbeService_fully_injectable`): script sha256 `4664b1c9996004669fcc84d7400bc1b1d68c1f86da83efe7df3fe6ce94c707dc`, event kinds `{\"runner-start\":1,\"stage\":4,\"funnel-candidates\":1,\"funnel-hook\":18,\"session-detached\":1}`; candidates include `__open*`, `open*`, `openat*`, `__syscall`, and `syscall`; no `funnel-hit` events observed.
- Run `book/experiments/frida-testing/out/18ef5758-937a-4e9c-b54d-db999d23a270` (sandbox_trace initial attempt on `ProbeService_fully_injectable`): script sha256 `6207b3a1c2378a1e26a6454003b9e8710c2f0a8f9e315d478b66bf776708465a`, event kinds `{\"runner-start\":1,\"stage\":4,\"error\":1,\"session-detached\":1}`; error `TypeError: not a function` from `Module.findExportByName`.
- Run `book/experiments/frida-testing/out/227d3232-9da5-463d-bab4-2f7bbbfc03ae` (sandbox_trace on `ProbeService_fully_injectable`): script sha256 `e0753d40450b1135c1b4ad79d6d902108de9a9bac9a642f826f2173c8359ba04`, event kinds `{\"runner-start\":1,\"stage\":4,\"sandbox-trace\":1,\"session-detached\":1}`; trace status `symbol-missing`, summary in `book/experiments/frida-testing/out/227d3232-9da5-463d-bab4-2f7bbbfc03ae/sandbox_trace_summary.json` (trace_exists false).
- Run `book/experiments/frida-testing/out/0ee1b6e3-f000-4037-aaee-23ce3e7f0098` (file-decision funnel on `ProbeService_fully_injectable`): script sha256 `43976ac03198182d3977e66631b3f2762eab4c72fd28db5a2dc4c67b246f17f0`, event kinds `{\"runner-start\":1,\"stage\":4,\"funnel-candidates\":3,\"funnel-hook\":41,\"funnel-hit\":2,\"session-detached\":1}`; `funnel-hit` events observed for `__open` and `open` with errno 13 on the deny path.

## Blockers / risks
- Spawn runs are terminating before any send() payloads are recorded; treat spawn as unstable on this host until proven otherwise.
- Attach-first smoke run triggered frida-helper and target crashes; the helper crash suggests a Frida-layer instability and the target died with a code signing invalid-page kill.
- Attach-first smoke run against `ProbeService_debuggable` also ended in a code signing invalid-page kill, with a frida-helper SIGILL crash reported.
- `ProbeService_fully_injectable` is attachable (smoke + export inventory); `fs_open` events can be forced via self-open, but `fs_op` does not emit fs-open events even when run in the same PID via `--attach`.
- `sandbox_set_trace_path` is not exported from `libsystem_sandbox.dylib` in `ProbeService_fully_injectable` (trace gating is blocked for this target).
- File-decision funnel now observes `__open` and `open` errno 13 hits in `libsystem_kernel.dylib` during fs_op; the open path is no longer unknown, but sandbox trace is still unavailable.
- Running Frida inside the Codex harness sandbox can produce misleading “plumbing” crashes (for example, `frida.get_local_device()` SIGSEGV); run `frida-testing` captures from a normal Terminal session.

## Next steps
- Decide whether to load or resolve sandbox tracing via a different module or target (current symbol missing blocks trace gating).
- Use the funnel hits + backtrace to tie `fs_op` errno 13 to the in-process open path and update hooks accordingly.
