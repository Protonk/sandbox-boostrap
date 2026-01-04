# frida-testing

## Purpose
Establish attach-first Frida witnesses for in-process sandbox behavior using EntitlementJail's process zoo on the Sonoma baseline. This experiment is exploratory; it does not promote claims beyond substrate theory without fresh host evidence.

## Baseline & scope
- world_id: sonoma-14.4.1-23E224-arm64-dyld-a3a840f9 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world.json)
- Tools: EntitlementJail.app (book/tools/entitlement/EntitlementJail.app), Frida Python bindings, and book.api.entitlementjail.
- Scope: attach-first instrumentation inside EntitlementJail XPC services, with observer-first deny evidence capture.
- Out of scope: spawn-based Frida flows, new operation/filter names, or promotion to mappings/CARTON without validation outputs.

## Deliverables / expected outcomes
- Attach-first harness (API): book/api/entitlementjail/frida.py (wrapper in book/evidence/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py).
- Hook scripts (API): book/api/frida/hooks/ (smoke, fs_open_selftest, sandbox_check_minimal, sandbox_check_trace, execmem_trace).
- Experiment-only hooks: book/evidence/experiments/runtime-final-final/suites/frida-testing/hooks/ (fs_open, sandbox_trace, sandbox_export_isolation, etc.).
- Hook script for per-export isolation: book/evidence/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js.
- Hook script for extension selftest calls: book/evidence/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_extension_selftest.js.
- Output layout with manifest and observer logs under book/evidence/experiments/runtime-final-final/suites/frida-testing/out/<run_id>/.

## Plan & execution log
- Note: EntitlementJail v2.1.9 removes `--ack-risk` and the `fully_injectable` / `fully_injectable_extensions` profiles. Use `profile@injectable` digital twins; pre-update runs below are legacy.
- Completed: updated run_ej_frida.py to align with v2.1.9 (no --ack-risk, use profile@injectable).
- Completed: added on_wait_ready callback support in book/api/entitlementjail/wait.py to attach Frida before FIFO trigger.
- Completed: added run_ej_frida.py harness that runs capabilities_snapshot, attaches Frida, and captures EntitlementJail observer output.
- Completed: updated fs_open_selftest.js to accept a container-correct selftest path via RPC (FRIDA_SELFTEST_PATH fallback).
- Completed: labeled legacy unified-log scripts as deprecated; observer-first capture is now the default.
- Completed: removed legacy run artifacts from book/evidence/experiments/runtime-final-final/suites/frida-testing/out/.
- Completed: added sandbox_export_isolation.js hook and --frida-config support in run_ej_frida.py for per-export isolation.
- Completed: probe_catalog + smoke (run_id d8e2c72a-493d-4518-9dfa-b18b57a41e83) attached successfully; observer output captured (selftest prep failed; not needed).
- Completed: fs_op + smoke (run_id 41d1a763-bfc3-4dbf-9920-0335d001383b) attached successfully; run-xpc ok.
- Completed: fs_op + fs_open.js (run_id 54bf34f2-a672-4eb2-8598-08861103d2f3) attached successfully; hooks installed, no fs-open events because open succeeded (LOG_SUCCESSES=false).
- Completed: fs_op + fs_open.js (run_id 9e49bf0d-da44-4b2a-a928-af6a7ba6f274) attached successfully; permission_error with deny_evidence=not_found; no fs-open events observed.
- Completed: fs_op + fs_open.js (run_id c1fe32d2-b058-43ff-81ca-836e346af8fa) attached successfully; explicit tmp_dir path with chmod 000 produced errno 13 fs-open events and deny_evidence=captured.
- Attempted: fs_op + fs_open_selftest (run_id e1ee3f59-b895-49ab-ba4b-62d0bd27999b) failed with XPC connection error.
- Attempted: fs_op + fs_open_selftest (run_id 6ba32d45-72c2-48fe-9dbe-ffc5ba8753f9) failed with XPC connection error.
- Attempted: fs_op + fs_open_selftest (run_id 3317ec42-abe3-4ecb-a233-7e9ed5d3ca53) failed with XPC connection error even with trigger delay.
- Completed: probe_catalog + fs_open_selftest (run_id b218b156-0b63-4265-8dc5-7aec41de3981) attached successfully; self-open emitted errno 13 (EACCES) fs-open event.
- Completed: fs_op + fs_open_funnel.js (run_id 88533003-dc07-4b5a-96fa-30a157789c21) attached successfully; no funnel-hit events for errno 1/13 under downloads path-class.
- Completed: fs_op + fs_open_funnel.js (run_id dd0955c2-864a-4471-96b8-4b97e609f8b3) attached successfully; mkdirat returned errno 1 while creating the downloads harness dir (deny evidence captured).
- Completed: fs_op + fs_op_funnel.js (run_id da23cd52-d323-41ae-bac7-a50f8aefe3cd) logged mkdir/mkdirat calls regardless of errno (errno 17 in tmp, errno 2/1 in downloads harness path).
- Completed: probe_catalog + discover_sandbox_exports.js (run_id eca03911-40f3-4df0-a74d-9aba5f0c0c1e) enumerated libsystem_sandbox exports (87 sandbox_* symbols).
- Completed: probe_catalog + sandbox_trace.js (run_id 25d6ade2-0b08-40d2-b37c-fbcad882e11a) reported no sandbox_set_trace_path/vtrace exports (trace unavailable).
- Attempted: fs_op + fs_open_selftest under debuggable (run_id 59e0530c-0817-49ad-ad0c-d824c7186b2c) timed out; Frida attach failed (no run_xpc/manifest).
- Attempted: fs_op + fs_open_selftest under debuggable (run_id c134a17d-2147-4031-9874-610a2e9de20b) timed out again; Frida attach failed (no run_xpc/manifest).
- Attempted: fs_op + fs_open_selftest under plugin_host_relaxed (run_id 6baf62bd-00c2-4bca-9d9c-aa6cd4807187) run-xpc ok but Frida attach denied.
- Attempted: probe_catalog + smoke under dyld_env_enabled (run_id c15262bf-19b2-47c3-bc38-76234fd4bc3e) run-xpc ok but Frida attach denied.
- Attempted: probe_catalog + smoke under jit_map_jit (run_id 56efece2-00ed-4814-89a6-94de7649056a) run-xpc ok but Frida attach denied.
- Attempted: probe_catalog + smoke under jit_rwx_legacy (run_id cb3bde87-6cb3-47cc-99ab-fc25621445a1) run-xpc ok but Frida attach denied.
- Attempted: probe_catalog + smoke under get-task-allow (run_id 9a1301d7-c4c5-483b-a107-d27505905225) failed with XPC connection error (xpc_error).
- Completed: probe_catalog + smoke under fully_injectable (run_id 1459e42d-3293-4521-9f27-5e4305ac6cf0) attached successfully after EntitlementJail update.
- Attempted: probe_catalog + fs_open_selftest under minimal@injectable (run_id 7cf0b52b-e6a8-4b27-9503-180d4dc9ccd3) timed out; run_xpc/manifest missing.
- Completed: probe_catalog + fs_open_selftest under minimal@injectable (run_id b03ad4a9-d2b3-438e-a71c-cab0ec92b0f3) attached successfully; fs-open errno 13 observed; selftest preparation failed (PermissionError).
- Completed: probe_catalog + smoke under minimal@injectable (run_id 916d33bd-97fb-4cd1-9346-fe0c70faa542) attached successfully; wait/trigger ok.
- Attempted: probe_catalog + smoke under @injectable sweep (minimal, net_client, downloads_rw, user_selected_executable, bookmarks_app_scope, temporary_exception) failed with NSCocoaErrorDomain Code 4099 (error 159 - Sandbox restriction); no session_ready or Frida attach (run_ids 994d18ad-9656-4c07-952a-3cdeb5b8a2af, d30a92eb-4a42-49de-875d-747691edc42a, e3c2b193-59c8-4cd1-82cd-9475aff52238, ad8a7d53-5e05-429e-995f-346a6068ef44, f32fa4ed-9eef-48f0-a76e-cad99c5d27fc, bcf5e8b2-8c05-4932-93e0-61fdeb5ec42e).
- Completed: entitlement-jail health-check --profile minimal@injectable succeeded outside the harness sandbox (all probes ok).
- Completed: entitlement-jail xpc run --profile minimal@injectable probe_catalog succeeded outside the harness sandbox (probe_catalog returned).
- Completed: probe_catalog + smoke under @injectable sweep with elevated permissions succeeded (run_ids c474eb4e-57b9-4325-8e62-a140b4b14635, 49e69f56-c29b-492e-acf7-7c3e12827de8, e3d62720-ce97-48b8-a243-62b1a067635e, 9917a124-ce0e-4809-9d83-87bb8a10d731, 30c14e26-0f69-4d67-87e8-ca30cd01151a, 2d0dc547-22af-4305-9ba8-fecf2bc48cc1).
- Completed: fs_op + fs_open_selftest under minimal@injectable with elevated permissions (run_id 1d996a72-4c75-4f43-bb71-639f445fd31d) captured fs-open errno 13 on self-open.
- Completed: sandbox_check + sandbox_check_trace.js under minimal@injectable with elevated permissions (run_id 265ebd80-5536-444d-aaf3-dea3cdf7bb16) captured sandbox_check call for file-read-data (/etc/hosts).
- Completed: sandbox_check + sandbox_check_minimal.js under minimal@injectable with elevated permissions (run_id ecb71fb6-3213-4285-978d-33583472ccbd) captured sandbox_check call for file-read-data.
- Attempted: sandbox_extension issue_file under temporary_exception@injectable with sandbox_export_isolation.js (run_id a066da1c-a9c5-4879-b8b5-ee91f745bee8) failed with NSCocoaErrorDomain Code 4099 (error 159 - Sandbox restriction); no token.
- Completed: fs_op + fs_open_funnel.js with explicit denied path (run_id d36438ca-f9d1-4d8d-9840-0f31c090ffd6) captured open errno 13 events with backtraces; readlink hooks installed but no readlink events observed.
- Attempted: probe_catalog + sandbox_check_trace.js (run_id fdd4679d-599f-498e-b474-e32fc243c09c) failed with XPC connection error; no sandbox-call events observed.
- Attempted: fs_op + sandbox_check_trace.js (run_id 4f40aa49-92c8-41b9-9b20-4dd8d0634e68) failed with XPC connection error; no sandbox-call events observed.
- Completed: probe_catalog + execmem_trace.js (run_id cb747a39-41a8-4e1b-874d-ef732c15eb0a) captured mmap/dlopen surfaces with no PROT_EXEC or MAP_JIT flags.
- Completed: jit_map_jit + execmem_trace.js (run_id 5a6cbff3-8dcb-4a5c-b125-c7298bcfeab2) captured MAP_JIT mmap events and pthread_jit_write_protect_np toggles with backtraces into InProcessProbeCore.probeJitMapJit.
- Completed: fs_op + fs_open_funnel.js readlink (run_id 21f80aa0-315d-4b55-9f74-de0098be48f8) captured readlink errno 2 with backtrace into InProcessProbeCore.probeFsOp.
- Completed: jit_rwx_legacy + execmem_trace.js (run_id 1f3eadb2-ee07-40c3-aefd-d22f027392de) captured PROT_EXEC mmap failure (errno 13) with backtrace into InProcessProbeCore.probeJitRwxLegacy.
- Attempted: probe_catalog + sandbox_check_minimal.js (run_id e25b0c21-6ef6-45da-a85e-03e3cd365ff5) failed with XPC connection error; no sandbox-minimal-call events observed.
- Completed: fs_op + fs_open_funnel.js readlink (run_id 5475128c-90e3-4b02-bf8a-2b27b202c873) captured readlink errno 13 (EACCES) with backtrace into InProcessProbeCore.probeFsOp.
- Completed: fs_op + sandbox_check_minimal.js with post-trigger attach (run_id a4aa9464-c65d-4f81-847f-c7b4f001d3ef) ran without XPC error but recorded no sandbox-minimal-call events.
- Completed: fs_op_wait + sandbox_check_minimal.js with gated FIFO (run_id 31a9fdb4-2192-4988-8dc5-3a23aef6e181) ran without XPC error but recorded no sandbox-minimal-call events.
- Attempted: probe_catalog + sandbox_export_isolation.js (sandbox_check) (run_id 61944b88-78c8-480d-8176-320210f47308) failed with XPC connection invalidated (NSCocoaErrorDomain Code 4099, error 159 - Sandbox restriction); no Frida attach.
- Attempted: probe_catalog + sandbox_export_isolation.js (sandbox_check_bulk) (run_id 068168b1-205a-4b94-8a82-aeb3cac0888e) failed with XPC connection invalidated (NSCocoaErrorDomain Code 4099, error 159 - Sandbox restriction); no Frida attach.
- Completed: probe_catalog + sandbox_export_isolation.js (sandbox_check) (run_id 0c400964-8763-4fcf-ae93-8ffc25866b70) attached successfully; hook installed; no sandbox-export-call events observed.
- Completed: probe_catalog + sandbox_export_isolation.js (sandbox_check_bulk) (run_id 71cbf237-598d-40cf-aeac-60d7f538fde2) attached successfully; hook installed; no sandbox-export-call events observed.
- Completed: sandbox_check + sandbox_export_isolation.js (sandbox_check) (run_id 2960d7bd-3555-402d-b301-93001d0988d5) captured sandbox-export-call for file-read-data (/etc/hosts); ret_i32 1.
- Completed: sandbox_check + sandbox_export_isolation.js (sandbox_extension_issue_file) (run_id 359239c3-a0d2-4750-9ed8-dad37b29eabc) attached successfully; hook installed; no sandbox-export-call events observed.
- Completed: sandbox_check + sandbox_export_isolation.js (sandbox_extension_issue_mach) (run_id 7feb2f90-026e-41b6-a89a-0950680b6103) attached successfully; hook installed; no sandbox-export-call events observed.
- Completed: sandbox_check + sandbox_export_isolation.js (sandbox_extension_consume) (run_id f20641ce-63e7-40b6-9d38-3659fcb1246a) attached successfully; hook installed; no sandbox-export-call events observed.
- Completed: sandbox_check + sandbox_export_isolation.js (sandbox_extension_release) (run_id 99e1a08e-f60e-49cf-a2b3-61b9d4d89b3a) attached successfully; hook installed; no sandbox-export-call events observed.
- Completed: probe_catalog + sandbox_extension_selftest.js (run_id 3866d936-2c9b-4322-a361-60821ab25ae9) attempted sandbox_extension_issue_file for /etc/hosts; issue failed errno 1; no consume/release.
- Completed: fs_op + smoke under fully_injectable_extensions (run_id d5968de8-abeb-459f-9cc1-10bb4e997522) created a harness file under run_dir; file missing by the time of extension issue.
- Attempted: sandbox_extension issue_file with harness path (run_id 976bbb19-00f8-4590-b48f-062dae251f11) failed with errno 2 (No such file or directory).
- Attempted: fs_op + smoke with target base (run_id a26f236f-166c-4321-817c-a995f951a426) failed (errno 21, Is a directory; name ignored).
- Attempted: fs_op + smoke with target harness_dir (run_id 8a907c5b-79af-4e6e-9381-b1485c6dd6bf) failed (errno 21, Is a directory; name ignored).
- Completed: sandbox_extension issue_file + sandbox_export_isolation.js (run_id 0bc59fb9-6ef6-448b-8fb2-29a403913b3e) issued token for /etc/hosts with --allow-unsafe-path; hook captured sandbox_extension_issue_file call.
- Attempted: sandbox_extension consume in minimal with short token (run_id 9b94fb08-cf29-482f-ab86-dac6995b8801) failed (errno 22, Invalid argument); Frida attach denied.
- Attempted: sandbox_extension consume in minimal with full token (run_id 3636ac13-d8f1-43c8-a2fb-e15ea5f7dab5) failed (errno 17, File exists); Frida attach denied.
- Attempted: sandbox_extension release in minimal with full token (run_id 1d2adecd-8894-488a-96b7-5eedd27593ca) failed (errno 22, Invalid argument); Frida attach denied.
- Attempted: sandbox_extension consume in fully_injectable_extensions with full token (run_id 15d6f3ec-da32-4fe9-a765-407c3990ac82) failed (errno 17, File exists); hook captured sandbox_extension_consume call.
- Attempted: sandbox_extension release in fully_injectable_extensions with full token (run_id 335f82f3-3a70-4070-818d-22a7d3bfe3cd) failed (errno 22, Invalid argument); hook captured sandbox_extension_release call.

## Evidence & artifacts
- Harness (API): book/api/entitlementjail/frida.py (wrapper: book/evidence/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py).
- Hooks (API): book/api/frida/hooks/smoke.js, book/api/frida/hooks/fs_open_selftest.js, book/api/frida/hooks/sandbox_check_minimal.js, book/api/frida/hooks/sandbox_check_trace.js, book/api/frida/hooks/execmem_trace.js (experiment paths are symlinks).
- Hooks (experiment-only): book/evidence/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open.js, book/evidence/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_funnel.js, book/evidence/experiments/runtime-final-final/suites/frida-testing/hooks/fs_op_funnel.js, book/evidence/experiments/runtime-final-final/suites/frida-testing/hooks/discover_sandbox_exports.js, book/evidence/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_trace.js, book/evidence/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js, book/evidence/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_extension_selftest.js.
- Config inputs: book/evidence/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_check.json, book/evidence/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_check_bulk.json, book/evidence/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_issue_file.json, book/evidence/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_issue_mach.json, book/evidence/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_consume.json, book/evidence/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_release.json, book/evidence/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_selftest.json.
- EntitlementJail wait API: book/api/entitlementjail/wait.py (on_wait_ready callback).
- Legacy note: runs that reference removed profiles are pre-v2.1.9 artifacts; refresh them under `profile@injectable` as needed.
- Successful runs:
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/d8e2c72a-493d-4518-9dfa-b18b57a41e83/manifest.json (probe_catalog + smoke).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/41d1a763-bfc3-4dbf-9920-0335d001383b/manifest.json (fs_op + smoke).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/54bf34f2-a672-4eb2-8598-08861103d2f3/manifest.json (fs_op + fs_open.js).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/9e49bf0d-da44-4b2a-a928-af6a7ba6f274/manifest.json (fs_op + fs_open.js + downloads path-class; no fs-open events).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/c1fe32d2-b058-43ff-81ca-836e346af8fa/manifest.json (fs_op + fs_open.js + explicit tmp_dir path; fs-open events captured).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/88533003-dc07-4b5a-96fa-30a157789c21/manifest.json (fs_op + fs_open_funnel.js + downloads path-class; no funnel-hit events).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/dd0955c2-864a-4471-96b8-4b97e609f8b3/manifest.json (fs_op + fs_open_funnel.js + downloads path-class; mkdirat errno 1).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/da23cd52-d323-41ae-bac7-a50f8aefe3cd/manifest.json (fs_op + fs_op_funnel.js + downloads path-class; mkdir/mkdirat errno evidence).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/eca03911-40f3-4df0-a74d-9aba5f0c0c1e/manifest.json (probe_catalog + discover_sandbox_exports.js).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/25d6ade2-0b08-40d2-b37c-fbcad882e11a/manifest.json (probe_catalog + sandbox_trace.js; trace unavailable).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/b218b156-0b63-4265-8dc5-7aec41de3981/manifest.json (probe_catalog + fs_open_selftest).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/b03ad4a9-d2b3-438e-a71c-cab0ec92b0f3/manifest.json (probe_catalog + fs_open_selftest under minimal@injectable).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/916d33bd-97fb-4cd1-9346-fe0c70faa542/manifest.json (probe_catalog + smoke under minimal@injectable).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/c474eb4e-57b9-4325-8e62-a140b4b14635/manifest.json (probe_catalog + smoke under minimal@injectable; elevated).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/49e69f56-c29b-492e-acf7-7c3e12827de8/manifest.json (probe_catalog + smoke under net_client@injectable; elevated).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/e3d62720-ce97-48b8-a243-62b1a067635e/manifest.json (probe_catalog + smoke under downloads_rw@injectable; elevated).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/9917a124-ce0e-4809-9d83-87bb8a10d731/manifest.json (probe_catalog + smoke under user_selected_executable@injectable; elevated).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/30c14e26-0f69-4d67-87e8-ca30cd01151a/manifest.json (probe_catalog + smoke under bookmarks_app_scope@injectable; elevated).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/2d0dc547-22af-4305-9ba8-fecf2bc48cc1/manifest.json (probe_catalog + smoke under temporary_exception@injectable; elevated).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/1459e42d-3293-4521-9f27-5e4305ac6cf0/manifest.json (probe_catalog + smoke under fully_injectable after update).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/1d996a72-4c75-4f43-bb71-639f445fd31d/manifest.json (fs_op + fs_open_selftest under minimal@injectable; elevated).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/265ebd80-5536-444d-aaf3-dea3cdf7bb16/manifest.json (sandbox_check + sandbox_check_trace under minimal@injectable; elevated).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/ecb71fb6-3213-4285-978d-33583472ccbd/manifest.json (sandbox_check + sandbox_check_minimal under minimal@injectable; elevated).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/d36438ca-f9d1-4d8d-9840-0f31c090ffd6/manifest.json (fs_op + fs_open_funnel.js denied path).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/cb747a39-41a8-4e1b-874d-ef732c15eb0a/manifest.json (probe_catalog + execmem_trace.js).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/5a6cbff3-8dcb-4a5c-b125-c7298bcfeab2/manifest.json (jit_map_jit + execmem_trace.js).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/21f80aa0-315d-4b55-9f74-de0098be48f8/manifest.json (fs_op + fs_open_funnel.js readlink).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/1f3eadb2-ee07-40c3-aefd-d22f027392de/manifest.json (jit_rwx_legacy + execmem_trace.js).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/5475128c-90e3-4b02-bf8a-2b27b202c873/manifest.json (fs_op + fs_open_funnel.js readlink EACCES).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/a4aa9464-c65d-4f81-847f-c7b4f001d3ef/manifest.json (fs_op + sandbox_check_minimal.js post-trigger attach).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/31a9fdb4-2192-4988-8dc5-3a23aef6e181/manifest.json (fs_op_wait + sandbox_check_minimal.js gated FIFO).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/0c400964-8763-4fcf-ae93-8ffc25866b70/manifest.json (sandbox_export_isolation + sandbox_check; hook installed, no calls).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/71cbf237-598d-40cf-aeac-60d7f538fde2/manifest.json (sandbox_export_isolation + sandbox_check_bulk; hook installed, no calls).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/2960d7bd-3555-402d-b301-93001d0988d5/manifest.json (sandbox_check + sandbox_export_isolation; sandbox_check call observed).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/359239c3-a0d2-4750-9ed8-dad37b29eabc/manifest.json (sandbox_export_isolation + sandbox_extension_issue_file; hook installed, no calls).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/7feb2f90-026e-41b6-a89a-0950680b6103/manifest.json (sandbox_export_isolation + sandbox_extension_issue_mach; hook installed, no calls).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/f20641ce-63e7-40b6-9d38-3659fcb1246a/manifest.json (sandbox_export_isolation + sandbox_extension_consume; hook installed, no calls).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/99e1a08e-f60e-49cf-a2b3-61b9d4d89b3a/manifest.json (sandbox_export_isolation + sandbox_extension_release; hook installed, no calls).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/3866d936-2c9b-4322-a361-60821ab25ae9/manifest.json (sandbox_extension_selftest; issue attempt failed errno 1).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/d5968de8-abeb-459f-9cc1-10bb4e997522/manifest.json (fs_op + smoke under fully_injectable_extensions; harness file created under run_dir).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/0bc59fb9-6ef6-448b-8fb2-29a403913b3e/manifest.json (sandbox_extension issue_file /etc/hosts; token issued; hook captured call).
- Probe-error runs (run-xpc ok, probe returned error):
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/976bbb19-00f8-4590-b48f-062dae251f11/manifest.json (sandbox_extension issue_file harness path; errno 2).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/a26f236f-166c-4321-817c-a995f951a426/manifest.json (fs_op target base; errno 21).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/8a907c5b-79af-4e6e-9381-b1485c6dd6bf/manifest.json (fs_op target harness_dir; errno 21).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/15d6f3ec-da32-4fe9-a765-407c3990ac82/manifest.json (sandbox_extension consume; errno 17; hook captured call).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/335f82f3-3a70-4070-818d-22a7d3bfe3cd/manifest.json (sandbox_extension release; errno 22; hook captured call).
- Partial runs (Frida attach denied):
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/6baf62bd-00c2-4bca-9d9c-aa6cd4807187/manifest.json (fs_op + fs_open_selftest under plugin_host_relaxed).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/c15262bf-19b2-47c3-bc38-76234fd4bc3e/manifest.json (probe_catalog + smoke under dyld_env_enabled).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/56efece2-00ed-4814-89a6-94de7649056a/manifest.json (probe_catalog + smoke under jit_map_jit).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/cb3bde87-6cb3-47cc-99ab-fc25621445a1/manifest.json (probe_catalog + smoke under jit_rwx_legacy).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/9a1301d7-c4c5-483b-a107-d27505905225/manifest.json (probe_catalog + smoke under get-task-allow; xpc_error).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/9b94fb08-cf29-482f-ab86-dac6995b8801/manifest.json (sandbox_extension consume short token; errno 22).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/3636ac13-d8f1-43c8-a2fb-e15ea5f7dab5/manifest.json (sandbox_extension consume full token; errno 17).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/1d2adecd-8894-488a-96b7-5eedd27593ca/manifest.json (sandbox_extension release full token; errno 22).
- Timed-out runs (manifest missing):
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/59e0530c-0817-49ad-ad0c-d824c7186b2c/ej/capabilities_snapshot.json (debuggable; Frida attach failed; run_xpc missing).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/c134a17d-2147-4031-9874-610a2e9de20b/ej/capabilities_snapshot.json (debuggable; Frida attach failed; run_xpc missing).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/7cf0b52b-e6a8-4b27-9503-180d4dc9ccd3/ej/capabilities_snapshot.json (minimal@injectable probe_catalog; harness timeout; run_xpc missing).
- Blocked runs (XPC connection error in harness sandbox):
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/e1ee3f59-b895-49ab-ba4b-62d0bd27999b/manifest.json.
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/6ba32d45-72c2-48fe-9dbe-ffc5ba8753f9/manifest.json.
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/3317ec42-abe3-4ecb-a233-7e9ed5d3ca53/manifest.json.
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/994d18ad-9656-4c07-952a-3cdeb5b8a2af/manifest.json (minimal@injectable sweep).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/d30a92eb-4a42-49de-875d-747691edc42a/manifest.json (net_client@injectable sweep).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/e3c2b193-59c8-4cd1-82cd-9475aff52238/manifest.json (downloads_rw@injectable sweep).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/ad8a7d53-5e05-429e-995f-346a6068ef44/manifest.json (user_selected_executable@injectable sweep).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/f32fa4ed-9eef-48f0-a76e-cad99c5d27fc/manifest.json (bookmarks_app_scope@injectable sweep).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/bcf5e8b2-8c05-4932-93e0-61fdeb5ec42e/manifest.json (temporary_exception@injectable sweep).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/a066da1c-a9c5-4879-b8b5-ee91f745bee8/manifest.json (sandbox_extension issue_file under temporary_exception@injectable).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/fdd4679d-599f-498e-b474-e32fc243c09c/manifest.json (sandbox_check_trace + probe_catalog).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/4f40aa49-92c8-41b9-9b20-4dd8d0634e68/manifest.json (sandbox_check_trace + fs_op).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/e25b0c21-6ef6-45da-a85e-03e3cd365ff5/manifest.json (sandbox_check_minimal + probe_catalog).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/61944b88-78c8-480d-8176-320210f47308/manifest.json (sandbox_export_isolation + sandbox_check; XPC connection invalidated).
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/068168b1-205a-4b94-8a82-aeb3cac0888e/manifest.json (sandbox_export_isolation + sandbox_check_bulk; XPC connection invalidated).
- Output layout (fresh runs only):
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/<run_id>/manifest.json
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/<run_id>/ej/run_xpc.json
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/<run_id>/ej/logs/run_xpc.log
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/<run_id>/ej/logs/observer/<...>
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/<run_id>/frida/meta.json
  - book/evidence/experiments/runtime-final-final/suites/frida-testing/out/<run_id>/frida/events.jsonl

## Run recipe (attach-first)
Example (attach via the @injectable digital twin):

```sh
./.venv/bin/python book/evidence/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py \
  --profile-id minimal@injectable \
  --probe-id fs_op \
  --script book/api/frida/hooks/fs_open_selftest.js \
  --probe-args --op open_read --path-class tmp --target specimen_file
```
Note: --probe-args consumes the remainder of the command line; keep it last.

Example (per-export isolation hook):

```sh
./.venv/bin/python book/evidence/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py \
  --profile-id minimal@injectable \
  --probe-id probe_catalog \
  --script book/evidence/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js \
  --frida-config-path book/evidence/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_check.json
```

## Blockers / risks
- Legacy runs use removed profiles (`fully_injectable`, `fully_injectable_extensions`, `get-task-allow`, `jit_map_jit`, `jit_rwx_legacy`, `dyld_env_enabled`, `plugin_host_relaxed`); treat those entries as historical and re-run under `profile@injectable` twins when needed.
- Frida spawn remains unstable on this host; this experiment is attach-first only (partial, no current witness).
- Attach-first fs_op + fs_open_selftest failed under legacy fully_injectable with NSCocoaErrorDomain Code 4097; rerun under minimal@injectable with elevated permissions succeeds (run_id 1d996a72-4c75-4f43-bb71-639f445fd31d).
- Frida attach can crash inside the Codex harness sandbox; run captures from a normal Terminal session.
- EntitlementJail xpc run/session fail with NSCocoaErrorDomain Code 4099 (error 159 - Sandbox restriction) inside the harness sandbox; elevated runs outside the sandbox succeed (health-check and @injectable sweep ok). Use elevated permissions for XPC sessions.
- sandbox_set_trace_path / vtrace exports were not present in libsystem_sandbox.dylib for legacy fully_injectable (run_id 25d6ade2-0b08-40d2-b37c-fbcad882e11a); trace unavailable until revalidated under @injectable.
- fs_op with downloads path-class produced permission_error without fs-open events; extended funnel captured mkdirat errno 1 during harness dir creation, indicating failure before open (partial).
- Frida attach failed for legacy profiles (get-task-allow, debuggable, plugin_host_relaxed, dyld_env_enabled, jit_map_jit, jit_rwx_legacy), limiting pre-update coverage.
- sandbox_check_trace.js succeeds under minimal@injectable with elevated permissions (run_id 265ebd80-5536-444d-aaf3-dea3cdf7bb16); harness sandbox still triggers XPC errors, so run elevated.
- sandbox_check_minimal.js succeeds under minimal@injectable with elevated permissions (run_id ecb71fb6-3213-4285-978d-33583472ccbd); earlier XPC errors were harness-only.
- sandbox_extension_selftest issue attempts failed with errno 1 under legacy fully_injectable; re-run under `temporary_exception@injectable`.
- sandbox_extension probe has a known bug (per user); skip it for now (prior consume/release anomalies remain unresolved).
- Base variants are not Frida-injectable (PermissionDeniedError); use `profile@injectable` twins for attach and `temporary_exception@injectable` for extension hooks.
- fs_op target base/harness_dir ignore --name and return errno 21 (Is a directory); run_dir files are cleaned before follow-on extension issue.
- EntitlementJail probes are defined inside the app bundle; sandbox_extension now exists, but probe source is still not in repo, so behavior is inferred from probe_catalog + run outputs.
- jit_rwx_legacy under legacy fully_injectable produced permission_error (errno 13) on RWX mmap despite allow-unsigned-executable-memory entitlement; treat RWX outcomes as partial until repeated.
- Post-trigger attach avoids XPC errors for sandbox_check_minimal.js, but no sandbox_check calls were observed even with gated fs_op_wait; userland sandbox_check may be unused by these probes (partial).
- Direct-path readlink with chmod 000 parent returns EACCES and logs via fs_open_funnel.js; some runs report exit_code -15 from run_xpc (cause unknown).
- If multiple service PIDs exist, the attach PID may not match data.details.service_pid; check manifest.json for pid_matches_service_pid.

## Next steps
- Use elevated permissions for future EntitlementJail runs and re-run any previously blocked @injectable probes to confirm the failures were sandbox-only.
- Compare the @injectable baseline sweep outputs (probe_catalog + capabilities_snapshot) across profiles and against base variants.
- Use sandbox_export_isolation.js to hook one libsystem_sandbox export at a time and identify a safe subset that does not trigger XPC errors; sandbox_check and sandbox_check_bulk hooks installed cleanly, and sandbox_check call capture succeeded under the dedicated probe.
- For deterministic fs-open error events, use an explicit tmp_dir path (chmod 000) with fs_op --path --allow-unsafe-path; this yielded errno 13 events and deny evidence.
- If fs-open events are still missing, use fs_open_funnel.js to widen symbol coverage before extending fs_open.js.
- If downloads path-class attribution is required, use fs_op_funnel.js and focus on mkdirat/rename paths rather than open hooks.
- If a future EntitlementJail build reintroduces sandbox_set_trace_path or vtrace exports, rerun sandbox_trace.js and record the new status.
- If deny evidence is needed, use EntitlementJail observer output and keep attribution explicit.
- If an EACCES readlink witness is required, try a direct path outside the container with --allow-unsafe-path and compare to the ENOENT readlink capture.
- If sandbox_check tracing is required, attempt a safer attach mode (for example, attach after run_xpc completes) and isolate which hooks trigger the XPC error.
- If sandbox_check evidence is required, target a probe that explicitly uses libsystem_sandbox APIs or add a dedicated probe inside EntitlementJail to call sandbox_check under controlled inputs.

## Appendix: legacy runs
Legacy run artifacts were removed from book/evidence/experiments/runtime-final-final/suites/frida-testing/out/. No current host witness remains; treat any inference as provisional until new runs are captured.
