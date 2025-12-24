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

## Evidence & artifacts
- Bootstrap target: `book/experiments/frida-testing/targets/open_loop.c`.
- Bootstrap binary: `book/experiments/frida-testing/targets/open_loop`.
- Hooks: `book/experiments/frida-testing/hooks/fs_open.js`, `book/experiments/frida-testing/hooks/fs_open_selftest.js`, and `book/experiments/frida-testing/hooks/discover_sandbox_exports.js`.
- Smoke hook: `book/experiments/frida-testing/hooks/smoke.js`.
- Runner: `book/experiments/frida-testing/run_frida.py`.

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
- Run `book/experiments/frida-testing/out/56577123-16b4-4335-be63-3478e63a7c88` (fs_open self-open on `ProbeService_fully_injectable`): script sha256 `151ffdc95b52c5afbb92263537a761643d24522815e15804a726ec73fef02e52`, event kinds `{\"runner-start\":1,\"stage\":4,\"hook-installed\":3,\"self-open\":1,\"fs-open\":1,\"session-detached\":1}`; errno histogram `{\"13\":1}` for `/Users/achyland/Library/Containers/com.yourteam.entitlement-jail.ProbeService_fully_injectable/Data/tmp/ej_noaccess`.

## Blockers / risks
- Spawn runs are terminating before any send() payloads are recorded; treat spawn as unstable on this host until proven otherwise.
- Attach-first smoke run triggered frida-helper and target crashes; the helper crash suggests a Frida-layer instability and the target died with a code signing invalid-page kill.
- Attach-first smoke run against `ProbeService_debuggable` also ended in a code signing invalid-page kill, with a frida-helper SIGILL crash reported.
- `ProbeService_fully_injectable` is attachable (smoke + export inventory); `fs_open` events can be forced via self-open, but `fs_op` still runs in a different service PID.
- Running Frida inside the Codex harness sandbox can produce misleading “plumbing” crashes (for example, `frida.get_local_device()` SIGSEGV); run `frida-testing` captures from a normal Terminal session.

## Next steps
- Await instructions on target process and probe shape.
- Prefer attach-first plumbing until frida-helper/target crashes are understood.
