# frida-testing Notes

## Running log
- Note: EntitlementJail v2.1.9 removes `--ack-risk` and the `fully_injectable` / `fully_injectable_extensions` profiles; use `profile@injectable` digital twins going forward.
- Action: promoted stable Frida hooks to book/api/frida/hooks and linked the experiment hook paths to the API copies.
- Action: moved the EntitlementJail Frida harness into book/api/entitlementjail/frida.py; book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py now delegates to the API entrypoint.
- Action: added on_wait_ready callback support in book/api/entitlementjail/wait.py to enable pre-trigger Frida attach.
- Action: added book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py harness (capabilities_snapshot + attach-first run-xpc + observer capture + manifest).
- Action: updated book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_selftest.js to accept FRIDA_SELFTEST_PATH via RPC/config.
- Action: marked capture_sandbox_log.py and parse_sandbox_log.py as legacy (observer-first capture is the default).
- Action: removed legacy run artifacts under book/experiments/runtime-final-final/suites/frida-testing/out/.
- Follow-up: run run_ej_frida.py outside the harness to capture new out/<run_id> artifacts.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_selftest.js --probe-args --op open_read --path-class tmp --target specimen_file
- Result: run-xpc exited 1 with NSCocoaErrorDomain Code 4097 (connection to service named com.yourteam.entitlement-jail.ProbeService_fully_injectable); stdout JSON missing, log stream missing; Frida attached to PID 77857 and session detached after process termination.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/e1ee3f59-b895-49ab-ba4b-62d0bd27999b/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/e1ee3f59-b895-49ab-ba4b-62d0bd27999b/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/e1ee3f59-b895-49ab-ba4b-62d0bd27999b/frida/events.jsonl.
- Status: blocked (no run-xpc witness JSON, service_pid missing).
- Follow-up: rerun with a clean service launch; inspect whether Frida attach is causing the XPC service to exit early.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/smoke.js
- Result: run-xpc ok; attach succeeded with pid_matches_service_pid true; observer reports captured; selftest path preparation failed with PermissionError (not needed for smoke).
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/d8e2c72a-493d-4518-9dfa-b18b57a41e83/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/d8e2c72a-493d-4518-9dfa-b18b57a41e83/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/d8e2c72a-493d-4518-9dfa-b18b57a41e83/frida/events.jsonl.
- Status: ok (attach works with smoke).
- Follow-up: avoid selftest preparation when using non-selftest hooks.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/smoke.js --no-prepare-selftest --probe-args --op open_read --path-class tmp --target specimen_file
- Result: run-xpc ok; attach succeeded with pid_matches_service_pid true; smoke hook emitted as expected; no deny evidence in observer output.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/41d1a763-bfc3-4dbf-9920-0335d001383b/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/41d1a763-bfc3-4dbf-9920-0335d001383b/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/41d1a763-bfc3-4dbf-9920-0335d001383b/frida/events.jsonl.
- Status: ok (attach + fs_op works without hooks).
- Follow-up: try fs_open hooks now that attach is stable.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open.js --no-prepare-selftest --probe-args --op open_read --path-class tmp --target specimen_file
- Result: run-xpc ok; attach succeeded with pid_matches_service_pid true; fs_open hooks installed; no fs-open events emitted (open succeeded; LOG_SUCCESSES=false); script-config-error reported (configure missing).
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/54bf34f2-a672-4eb2-8598-08861103d2f3/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/54bf34f2-a672-4eb2-8598-08861103d2f3/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/54bf34f2-a672-4eb2-8598-08861103d2f3/frida/events.jsonl.
- Status: partial (hooks installed, but no error events for successful open).
- Follow-up: choose a deny path or enable success logging if we need fs-open events.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_selftest.js --no-prepare-selftest --probe-args --op open_read --path-class tmp --target specimen_file
- Result: run-xpc exited 1 with NSCocoaErrorDomain Code 4097 (connection to service named com.yourteam.entitlement-jail.ProbeService_fully_injectable); stdout JSON missing, log stream missing; Frida session detached after process termination.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/6ba32d45-72c2-48fe-9dbe-ffc5ba8753f9/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/6ba32d45-72c2-48fe-9dbe-ffc5ba8753f9/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/6ba32d45-72c2-48fe-9dbe-ffc5ba8753f9/frida/events.jsonl.
- Status: blocked (fs_open_selftest + fs_op not stable).
- Follow-up: retry with delay or alternate probe if selftest is required.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_selftest.js --no-prepare-selftest --trigger-delay-s 1.0 --attach-timeout-s 10 --probe-args --op open_read --path-class tmp --target specimen_file
- Result: run-xpc exited 1 with NSCocoaErrorDomain Code 4097; stdout JSON missing, log stream missing; delay did not help.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/3317ec42-abe3-4ecb-a233-7e9ed5d3ca53/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/3317ec42-abe3-4ecb-a233-7e9ed5d3ca53/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/3317ec42-abe3-4ecb-a233-7e9ed5d3ca53/frida/events.jsonl.
- Status: blocked (fs_open_selftest + fs_op still unstable).
- Follow-up: treat fs_open_selftest + fs_op as blocked until a different attach strategy is available.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_selftest.js --no-prepare-selftest
- Result: run-xpc ok; attach succeeded with pid_matches_service_pid true; self-open executed and emitted fs-open with errno 13 (EACCES).
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/b218b156-0b63-4265-8dc5-7aec41de3981/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/b218b156-0b63-4265-8dc5-7aec41de3981/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/b218b156-0b63-4265-8dc5-7aec41de3981/frida/events.jsonl.
- Status: ok (fs_open_selftest works with probe_catalog).
- Follow-up: if fs_op needs selftest, consider running fs_open_selftest in a separate attach window from the fs_op probe.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open.js --skip-capabilities --service-name ProbeService_fully_injectable --probe-args --op open_read --path-class downloads --target specimen_file
- Result: run-xpc permission_error (errno=1) with deny_evidence=not_found; hooks installed, no fs-open events emitted.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/9e49bf0d-da44-4b2a-a928-af6a7ba6f274/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/9e49bf0d-da44-4b2a-a928-af6a7ba6f274/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/9e49bf0d-da44-4b2a-a928-af6a7ba6f274/frida/events.jsonl.
- Status: partial (deny evidence missing; fs-open hooks did not observe the failure).
- Follow-up: force a direct open error via --path + chmod 000 to confirm hook coverage.

- Prep: created details.tmp_dir/ej_frida_denied.txt and chmod 000; removed after run.
- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open.js --skip-capabilities --service-name ProbeService_fully_injectable --probe-args --op open_read --path /Users/achyland/Library/Containers/com.yourteam.entitlement-jail.ProbeService_fully_injectable/Data/tmp/ej_frida_denied.txt --allow-unsafe-path
- Result: run-xpc permission_error (errno=13) with deny_evidence=captured; fs_open emitted __open/open events with errno 13 and backtrace frames pointing into InProcessProbeCore.probeFsOp.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/c1fe32d2-b058-43ff-81ca-836e346af8fa/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/c1fe32d2-b058-43ff-81ca-836e346af8fa/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/c1fe32d2-b058-43ff-81ca-836e346af8fa/frida/events.jsonl.
- Status: ok (fs-open error events captured with deny evidence).
- Follow-up: use the explicit tmp_dir path + chmod 000 as the default deny-path recipe for fs_open.js.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_funnel.js --skip-capabilities --service-name ProbeService_fully_injectable --probe-args --op open_read --path-class downloads --target specimen_file
- Result: run-xpc permission_error (errno=1) with deny_evidence=not_found; funnel hooks installed but no funnel-hit events (no errno 1/13 from open/openat/access/syscall).
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/88533003-dc07-4b5a-96fa-30a157789c21/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/88533003-dc07-4b5a-96fa-30a157789c21/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/88533003-dc07-4b5a-96fa-30a157789c21/frida/events.jsonl.
- Status: partial (downloads path-class failure did not surface via open/syscall hooks).
- Follow-up: treat downloads path-class permission_error as occurring before open; use explicit tmp_dir deny path when fs-open events are required.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/discover_sandbox_exports.js --skip-capabilities --service-name ProbeService_fully_injectable
- Result: exports from libsystem_sandbox.dylib enumerated; 87 sandbox_* exports captured; no errors.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/eca03911-40f3-4df0-a74d-9aba5f0c0c1e/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/eca03911-40f3-4df0-a74d-9aba5f0c0c1e/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/eca03911-40f3-4df0-a74d-9aba5f0c0c1e/frida/events.jsonl.
- Status: ok (export enumeration worked).
- Follow-up: use this export list to confirm sandbox_set_trace_path/vtrace availability.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_trace.js --skip-capabilities --service-name ProbeService_fully_injectable
- Result: sandbox_trace reported no sandbox_set_trace_path, sandbox_vtrace_enable, or sandbox_vtrace_report exports in libsystem_sandbox.dylib; trace unavailable.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/25d6ade2-0b08-40d2-b37c-fbcad882e11a/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/25d6ade2-0b08-40d2-b37c-fbcad882e11a/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/25d6ade2-0b08-40d2-b37c-fbcad882e11a/frida/events.jsonl.
- Status: blocked (no trace exports to exercise).
- Follow-up: treat sandbox trace as unavailable on this host until a new export witness appears.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id debuggable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_selftest.js --attach-seconds 60 --hold-open-seconds 40 --attach-timeout-s 10 --probe-args --op open_read --path-class tmp --target specimen_file
- Result: command timed out; frida attach failed with "refused to load frida-agent, or terminated during injection"; run_xpc/manifest not written.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/59e0530c-0817-49ad-ad0c-d824c7186b2c/ej/capabilities_snapshot.json; book/experiments/runtime-final-final/suites/frida-testing/out/59e0530c-0817-49ad-ad0c-d824c7186b2c/frida/events.jsonl.
- Status: blocked (debuggable does not permit Frida attach in this run).
- Follow-up: try a different profile or service for attach; avoid long attach windows in the harness time limit.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id debuggable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_selftest.js --attach-seconds 60 --hold-open-seconds 40 --attach-timeout-s 10 --probe-args --op open_read --path-class tmp --target specimen_file
- Result: second attempt timed out again; frida attach failed with the same error; run_xpc/manifest not written.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/c134a17d-2147-4031-9874-610a2e9de20b/ej/capabilities_snapshot.json; book/experiments/runtime-final-final/suites/frida-testing/out/c134a17d-2147-4031-9874-610a2e9de20b/frida/events.jsonl.
- Status: blocked (repeatable attach failure under debuggable).
- Follow-up: treat debuggable as non-attachable for Frida in this experiment unless EntitlementJail changes.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id plugin_host_relaxed --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_selftest.js --attach-seconds 45 --hold-open-seconds 20 --attach-timeout-s 10 --probe-args --op open_read --path-class tmp --target specimen_file
- Result: run-xpc ok; frida attach failed with "unable to access process with pid ... from the current user account"; no fs-open events.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/6baf62bd-00c2-4bca-9d9c-aa6cd4807187/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/6baf62bd-00c2-4bca-9d9c-aa6cd4807187/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/6baf62bd-00c2-4bca-9d9c-aa6cd4807187/frida/events.jsonl.
- Status: blocked (Frida attach denied for plugin_host_relaxed).
- Follow-up: keep attach-first work on fully_injectable; other profiles appear to block Frida injection on this host.

- Action: expanded fs_open_funnel.js to include mkdir/rename/unlink/creat/rmdir syscalls for fs_op failures.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id dyld_env_enabled --ack-risk dyld_env_enabled --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/smoke.js --skip-capabilities --service-name ProbeService_dyld_env_enabled
- Result: run-xpc ok; frida attach denied with PermissionDeniedError (unable to access process pid).
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/c15262bf-19b2-47c3-bc38-76234fd4bc3e/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/c15262bf-19b2-47c3-bc38-76234fd4bc3e/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/c15262bf-19b2-47c3-bc38-76234fd4bc3e/frida/events.jsonl.
- Status: blocked (attach denied).
- Follow-up: treat dyld_env_enabled as non-attachable for Frida on this host.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id jit_map_jit --ack-risk jit_map_jit --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/smoke.js --skip-capabilities --service-name ProbeService_jit_map_jit
- Result: run-xpc ok; frida attach denied with PermissionDeniedError (unable to access process pid).
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/56efece2-00ed-4814-89a6-94de7649056a/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/56efece2-00ed-4814-89a6-94de7649056a/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/56efece2-00ed-4814-89a6-94de7649056a/frida/events.jsonl.
- Status: blocked (attach denied).
- Follow-up: treat jit_map_jit as non-attachable for Frida on this host.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id jit_rwx_legacy --ack-risk jit_rwx_legacy --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/smoke.js --skip-capabilities --service-name ProbeService_jit_rwx_legacy
- Result: run-xpc ok; frida attach denied with PermissionDeniedError (unable to access process pid).
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/cb3bde87-6cb3-47cc-99ab-fc25621445a1/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/cb3bde87-6cb3-47cc-99ab-fc25621445a1/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/cb3bde87-6cb3-47cc-99ab-fc25621445a1/frida/events.jsonl.
- Status: blocked (attach denied).
- Follow-up: treat jit_rwx_legacy as non-attachable for Frida on this host.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_funnel.js --skip-capabilities --service-name ProbeService_fully_injectable --probe-args --op open_read --path-class downloads --target specimen_file
- Result: run-xpc permission_error (errno=1) with deny_evidence=captured; funnel-hit recorded for mkdirat with errno 1 while creating the downloads harness dir; no open/openat hits.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/dd0955c2-864a-4471-96b8-4b97e609f8b3/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/dd0955c2-864a-4471-96b8-4b97e609f8b3/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/dd0955c2-864a-4471-96b8-4b97e609f8b3/frida/events.jsonl.
- Status: partial (downloads path-class failure observed at mkdirat; not an open hook).
- Follow-up: consider adding mkdirat to a dedicated fs_op funnel script or extending fs_open.js if we want per-op attribution.

- Action: added book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_op_funnel.js to log mkdir/rename/unlink/creat/rmdir calls regardless of errno.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_op_funnel.js --skip-capabilities --service-name ProbeService_fully_injectable --probe-args --op open_read --path-class downloads --target specimen_file
- Result: run-xpc permission_error (errno=1) with deny_evidence=captured; fs-op-funnel logged mkdir/mkdirat calls (errno 17 in tmp, errno 2 and errno 1 in downloads harness path) with backtraces into InProcessProbeCore.probeFsOp.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/da23cd52-d323-41ae-bac7-a50f8aefe3cd/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/da23cd52-d323-41ae-bac7-a50f8aefe3cd/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/da23cd52-d323-41ae-bac7-a50f8aefe3cd/frida/events.jsonl.
- Status: partial (downloads path-class failure observed at mkdirat; open not reached).
- Follow-up: use fs_op_funnel.js when mapping downloads path-class failures; add path_substr config if log volume grows.

- Action: updated book/api/entitlementjail/wait.py to create missing FIFO and avoid blocking opens for attach waits.
- Action: added sandbox_export_isolation.js and --frida-config support in run_ej_frida.py for per-export libsystem_sandbox isolation.
- Action: added sandbox_export_isolation input configs under book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id get-task-allow --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/smoke.js --skip-capabilities --service-name ProbeService_get-task-allow
- Result: command timed out; frida attach failed with "refused to load frida-agent, or terminated during injection"; run_xpc/manifest not written.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/15defc62-509e-4e93-98c3-c5e9efa18561/frida/events.jsonl.
- Status: blocked (pre-fix hang).
- Follow-up: retry after wait.py fix with shorter attach window.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id get-task-allow --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/smoke.js --skip-capabilities --service-name ProbeService_get-task-allow --attach-seconds 5 --hold-open-seconds 0 --attach-timeout-s 5
- Result: command timed out again; frida attach failed with "refused to load frida-agent, or terminated during injection"; run_xpc/manifest not written.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/a1c5cfa5-3efa-49d4-b926-b7eb27ad4d4a/frida/events.jsonl.
- Status: blocked (pre-fix hang).
- Follow-up: retry after wait.py fix with shorter attach window.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id get-task-allow --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/smoke.js --skip-capabilities --service-name ProbeService_get-task-allow --attach-seconds 5 --hold-open-seconds 0 --attach-timeout-s 5
- Result: run-xpc failed with NSCocoaErrorDomain Code 4097 (xpc_error); frida attach error ProcessNotRespondingError; manifest written.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/9a1301d7-c4c5-483b-a107-d27505905225/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/9a1301d7-c4c5-483b-a107-d27505905225/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/9a1301d7-c4c5-483b-a107-d27505905225/frida/events.jsonl.
- Status: blocked (get-task-allow xpc_error during attach).
- Follow-up: treat get-task-allow as unstable for Frida attach on this host; use fully_injectable.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/smoke.js --skip-capabilities --service-name ProbeService_fully_injectable --attach-seconds 5 --hold-open-seconds 0 --attach-timeout-s 5
- Result: run-xpc ok; frida attach succeeded; pid_matches_service_pid true.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/1459e42d-3293-4521-9f27-5e4305ac6cf0/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/1459e42d-3293-4521-9f27-5e4305ac6cf0/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/1459e42d-3293-4521-9f27-5e4305ac6cf0/frida/events.jsonl.
- Status: ok (fully_injectable attach still works after update).
- Follow-up: use fully_injectable for attach-first hooks; keep get-task-allow as blocked.

- Action: extended fs_open_funnel.js to include readlink/readlinkat symbol coverage.
- Action: added sandbox_check_trace.js (sandbox_check/extension_issue trace hook).
- Action: added execmem_trace.js (mmap/mprotect/dlopen/pthread_jit_write_protect_np trace hook).
- Action: expanded fs_open_funnel.js error filter to include errno 2/22 for readlink/ENOENT coverage.
- Action: added sandbox_check_minimal.js (sandbox_check-only tracing).
- Action: added on_trigger callback support in book/api/entitlementjail/wait.py to enable post-trigger attach windows.
- Action: added --attach-stage and --post-trigger-attach-delay-s to run_ej_frida.py (attach after trigger).

- Prep: created /Users/achyland/Library/Containers/com.yourteam.entitlement-jail.ProbeService_fully_injectable/Data/tmp/ej_frida_denied.txt with chmod 000 to force an EACCES open.
- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_funnel.js --skip-capabilities --service-name ProbeService_fully_injectable --no-prepare-selftest --probe-args --op open_read --path /Users/achyland/Library/Containers/com.yourteam.entitlement-jail.ProbeService_fully_injectable/Data/tmp/ej_frida_denied.txt --allow-unsafe-path
- Result: run-xpc permission_error (errno=13) with deny_evidence=captured; funnel candidates now include readlink/readlinkat; funnel-hit events captured for open/open with errno 13 and backtraces into InProcessProbeCore.probeFsOp; no readlink hits in this run.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/d36438ca-f9d1-4d8d-9840-0f31c090ffd6/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/d36438ca-f9d1-4d8d-9840-0f31c090ffd6/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/d36438ca-f9d1-4d8d-9840-0f31c090ffd6/frida/events.jsonl.
- Status: ok (hooks installed; readlink coverage present but not exercised).
- Follow-up: if readlink coverage is needed, run fs_op --op readlink with a denied path or broaden logging to include non-EACCES errors.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_check_trace.js --skip-capabilities --service-name ProbeService_fully_injectable --no-prepare-selftest
- Result: run-xpc failed with NSCocoaErrorDomain Code 4097 (xpc_error); Frida attached and installed hooks; sandbox_check_trace reported candidate symbols but no sandbox-call events recorded before service exit.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/fdd4679d-599f-498e-b474-e32fc243c09c/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/fdd4679d-599f-498e-b474-e32fc243c09c/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/fdd4679d-599f-498e-b474-e32fc243c09c/frida/events.jsonl.
- Status: blocked (xpc_error; sandbox_check calls not observed).
- Follow-up: retry with a different probe or drop the sandbox_check hooks if they destabilize the service.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_check_trace.js --skip-capabilities --service-name ProbeService_fully_injectable --no-prepare-selftest --probe-args --op stat --path-class tmp --target specimen_file
- Result: run-xpc failed with NSCocoaErrorDomain Code 4097 (xpc_error); no sandbox-call events recorded.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/4f40aa49-92c8-41b9-9b20-4dd8d0634e68/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/4f40aa49-92c8-41b9-9b20-4dd8d0634e68/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/4f40aa49-92c8-41b9-9b20-4dd8d0634e68/frida/events.jsonl.
- Status: blocked (xpc_error; sandbox_check calls not observed).
- Follow-up: treat sandbox_check trace as destabilizing for fully_injectable unless a safer attach mode is found.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/execmem_trace.js --skip-capabilities --service-name ProbeService_fully_injectable --no-prepare-selftest
- Result: run-xpc ok; execmem_trace captured mmap and dlopen/dlclose calls (no PROT_EXEC/MAP_JIT in this run).
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/cb747a39-41a8-4e1b-874d-ef732c15eb0a/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/cb747a39-41a8-4e1b-874d-ef732c15eb0a/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/cb747a39-41a8-4e1b-874d-ef732c15eb0a/frida/events.jsonl.
- Status: partial (execmem surfaces observed; no exec/JIT flags in probe_catalog).
- Follow-up: run a JIT-focused probe (jit_map_jit) to confirm MAP_JIT capture.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id jit_map_jit --script book/experiments/runtime-final-final/suites/frida-testing/hooks/execmem_trace.js --skip-capabilities --service-name ProbeService_fully_injectable --no-prepare-selftest
- Result: run-xpc ok; execmem_trace captured MAP_JIT mmap calls and pthread_jit_write_protect_np toggles with backtraces into InProcessProbeCore.probeJitMapJit.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/5a6cbff3-8dcb-4a5c-b125-c7298bcfeab2/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/5a6cbff3-8dcb-4a5c-b125-c7298bcfeab2/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/5a6cbff3-8dcb-4a5c-b125-c7298bcfeab2/frida/events.jsonl.
- Status: ok (MAP_JIT surfaces captured under fully_injectable).
- Follow-up: consider a jit_rwx_legacy run if RWX mmap evidence is needed.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_funnel.js --skip-capabilities --service-name ProbeService_fully_injectable --no-prepare-selftest --probe-args --op readlink --path-class tmp --target specimen_file
- Result: run-xpc not_found (errno=2) with deny_evidence=captured; fs_open_funnel captured readlink with errno 2 and backtrace into InProcessProbeCore.probeFsOp; run_xpc exit_code -15 observed.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/21f80aa0-315d-4b55-9f74-de0098be48f8/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/21f80aa0-315d-4b55-9f74-de0098be48f8/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/21f80aa0-315d-4b55-9f74-de0098be48f8/frida/events.jsonl.
- Status: ok (readlink hook exercised; errno 2 captured).
- Follow-up: if we need an EACCES readlink witness, try a direct path outside the container with --allow-unsafe-path.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id jit_rwx_legacy --script book/experiments/runtime-final-final/suites/frida-testing/hooks/execmem_trace.js --skip-capabilities --service-name ProbeService_fully_injectable --no-prepare-selftest
- Result: run-xpc permission_error (errno=13) with deny_evidence=captured; execmem_trace captured mmap with PROT_EXEC (prot=7) returning -1 and backtrace into InProcessProbeCore.probeJitRwxLegacy.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/1f3eadb2-ee07-40c3-aefd-d22f027392de/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/1f3eadb2-ee07-40c3-aefd-d22f027392de/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/1f3eadb2-ee07-40c3-aefd-d22f027392de/frida/events.jsonl.
- Status: partial (RWX attempt observed; mmap failed with errno 13).
- Follow-up: compare with jit_map_jit to keep MAP_JIT vs RWX results aligned.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_check_minimal.js --skip-capabilities --service-name ProbeService_fully_injectable --no-prepare-selftest
- Result: run-xpc failed with NSCocoaErrorDomain Code 4097 (xpc_error); hooks installed (sandbox_check + sandbox_check_bulk) but no sandbox-minimal-call events observed before exit.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/e25b0c21-6ef6-45da-a85e-03e3cd365ff5/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/e25b0c21-6ef6-45da-a85e-03e3cd365ff5/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/e25b0c21-6ef6-45da-a85e-03e3cd365ff5/frida/events.jsonl.
- Status: blocked (sandbox_check hooking still destabilizes the XPC service).
- Follow-up: treat libsystem_sandbox hooks as unsafe on this host; consider post-run attachment or symbol-free alternatives if sandbox_check evidence is required.

- Prep: created /Users/achyland/Library/Containers/com.yourteam.entitlement-jail.ProbeService_fully_injectable/Data/tmp/ej_readlink_blocked/deny_link (symlink) and chmod 000 on parent dir to force readlink EACCES.
- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_funnel.js --skip-capabilities --service-name ProbeService_fully_injectable --no-prepare-selftest --probe-args --op readlink --path /Users/achyland/Library/Containers/com.yourteam.entitlement-jail.ProbeService_fully_injectable/Data/tmp/ej_readlink_blocked/deny_link --allow-unsafe-path
- Result: run-xpc permission_error (errno=13) with deny_evidence=captured; fs_open_funnel captured readlink errno 13 with backtrace into InProcessProbeCore.probeFsOp; run_xpc exit_code -15 observed.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/5475128c-90e3-4b02-bf8a-2b27b202c873/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/5475128c-90e3-4b02-bf8a-2b27b202c873/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/5475128c-90e3-4b02-bf8a-2b27b202c873/frida/events.jsonl.
- Status: ok (EACCES readlink witness captured).
- Follow-up: note run_xpc exit_code -15; keep an eye on whether it recurs for direct-path ops.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_check_minimal.js --skip-capabilities --service-name ProbeService_fully_injectable --no-prepare-selftest --attach-stage post-trigger --post-trigger-attach-delay-s 0.2 --probe-args --op stat --path-class tmp --target specimen_file
- Result: run-xpc not_found (errno=2) with deny_evidence=not_found; attach succeeded post-trigger (pid_matches_service_pid true); no sandbox-minimal-call events observed.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/a4aa9464-c65d-4f81-847f-c7b4f001d3ef/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/a4aa9464-c65d-4f81-847f-c7b4f001d3ef/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/a4aa9464-c65d-4f81-847f-c7b4f001d3ef/frida/events.jsonl.
- Status: partial (post-trigger attach avoids xpc_error, but no sandbox_check calls observed).
- Follow-up: attempt a delayed probe that waits on a FIFO to give hooks time to install.

- Prep: created /Users/achyland/Library/Containers/com.yourteam.entitlement-jail.ProbeService_fully_injectable/Data/tmp/ej_fsop_wait.fifo and triggered it after 3 seconds to gate the fs_op_wait probe.
- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id fs_op_wait --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_check_minimal.js --skip-capabilities --service-name ProbeService_fully_injectable --no-prepare-selftest --attach-stage post-trigger --post-trigger-attach-delay-s 0.2 --probe-args --op stat --path-class tmp --target specimen_file --wait-fifo /Users/achyland/Library/Containers/com.yourteam.entitlement-jail.ProbeService_fully_injectable/Data/tmp/ej_fsop_wait.fifo --wait-timeout-ms 10000
- Result: run-xpc not_found (errno=2) with deny_evidence=not_found; attach succeeded post-trigger; no sandbox-minimal-call events observed during the gated probe.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/31a9fdb4-2192-4988-8dc5-3a23aef6e181/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/31a9fdb4-2192-4988-8dc5-3a23aef6e181/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/31a9fdb4-2192-4988-8dc5-3a23aef6e181/frida/events.jsonl.
- Status: partial (sandbox_check still not observed even with gated probe).
- Follow-up: consider other probes likely to call sandbox_check, or treat userland sandbox_check as absent for these probes.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_check.json --no-prepare-selftest
- Result: run-xpc failed at session start; XPC connection invalidated; open_session_failed with NSCocoaErrorDomain Code 4099 (error 159 - Sandbox restriction); no Frida attach (pid_candidates empty; frida meta/events missing).
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/61944b88-78c8-480d-8176-320210f47308/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/61944b88-78c8-480d-8176-320210f47308/ej/run_xpc.json.
- Status: blocked (Codex harness sandbox blocked EntitlementJail XPC session).
- Follow-up: rerun from a normal Terminal session outside the harness; confirm EntitlementJail service launch before attaching.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_check_bulk.json --no-prepare-selftest
- Result: run-xpc failed at session start; XPC connection invalidated; open_session_failed with NSCocoaErrorDomain Code 4099 (error 159 - Sandbox restriction); no Frida attach (pid_candidates empty; frida meta/events missing).
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/068168b1-205a-4b94-8a82-aeb3cac0888e/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/068168b1-205a-4b94-8a82-aeb3cac0888e/ej/run_xpc.json.
- Status: blocked (Codex harness sandbox blocked EntitlementJail XPC session).
- Follow-up: rerun from a normal Terminal session outside the harness; confirm EntitlementJail service launch before attaching.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_check.json --no-prepare-selftest
- Result: run-xpc ok; attach succeeded (pid_matches_service_pid true); sandbox_export_isolation installed sandbox_check hook; no sandbox-export-call events observed (probe_catalog does not call sandbox_check); session detached on process exit.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/0c400964-8763-4fcf-ae93-8ffc25866b70/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/0c400964-8763-4fcf-ae93-8ffc25866b70/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/0c400964-8763-4fcf-ae93-8ffc25866b70/frida/events.jsonl.
- Status: partial (hook installed without XPC error; no calls observed in probe_catalog).
- Follow-up: run probe_id sandbox_check with --operation <sandbox-op> to exercise the hook.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_check_bulk.json --no-prepare-selftest
- Result: run-xpc ok; attach succeeded (pid_matches_service_pid true); sandbox_export_isolation installed sandbox_check_bulk hook; no sandbox-export-call events observed (probe_catalog does not call sandbox_check_bulk); session detached on process exit.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/71cbf237-598d-40cf-aeac-60d7f538fde2/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/71cbf237-598d-40cf-aeac-60d7f538fde2/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/71cbf237-598d-40cf-aeac-60d7f538fde2/frida/events.jsonl.
- Status: partial (hook installed without XPC error; no calls observed in probe_catalog).
- Follow-up: run probe_id sandbox_check with --operation <sandbox-op> to exercise the hook.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id sandbox_check --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_check.json --no-prepare-selftest --probe-args --operation file-read-data --path /etc/hosts
- Result: run-xpc ok; attach succeeded (pid_matches_service_pid true); sandbox_check hook installed; sandbox-export-call observed with args ["file-read-data", "/etc/hosts"] and ret_i32 1; session detached on process exit.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/2960d7bd-3555-402d-b301-93001d0988d5/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/2960d7bd-3555-402d-b301-93001d0988d5/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/2960d7bd-3555-402d-b301-93001d0988d5/frida/events.jsonl.
- Status: partial (sandbox_check hook captured a call under the dedicated probe).
- Follow-up: use sandbox_export_isolation.js with sandbox_extension_* exports to identify hooks that install cleanly; consider a dedicated extension-issue probe if no calls are observed.

- Action: escalation request was rejected by the harness policy; extension isolation runs proceeded in the default sandbox.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id sandbox_check --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_issue_file.json --no-prepare-selftest --probe-args --operation file-read-data --path /etc/hosts
- Result: run-xpc ok; attach succeeded (pid_matches_service_pid true); sandbox_extension_issue_file hook installed; no sandbox-export-call events observed during sandbox_check probe.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/359239c3-a0d2-4750-9ed8-dad37b29eabc/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/359239c3-a0d2-4750-9ed8-dad37b29eabc/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/359239c3-a0d2-4750-9ed8-dad37b29eabc/frida/events.jsonl.
- Status: partial (hook installed without XPC error; no calls observed).
- Follow-up: try a dedicated extension issue/consume/release selftest to force calls.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id sandbox_check --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_issue_mach.json --no-prepare-selftest --probe-args --operation file-read-data --path /etc/hosts
- Result: run-xpc ok; attach succeeded (pid_matches_service_pid true); sandbox_extension_issue_mach hook installed; no sandbox-export-call events observed during sandbox_check probe.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/7feb2f90-026e-41b6-a89a-0950680b6103/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/7feb2f90-026e-41b6-a89a-0950680b6103/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/7feb2f90-026e-41b6-a89a-0950680b6103/frida/events.jsonl.
- Status: partial (hook installed without XPC error; no calls observed).
- Follow-up: try a dedicated extension issue/consume/release selftest to force calls.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id sandbox_check --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_consume.json --no-prepare-selftest --probe-args --operation file-read-data --path /etc/hosts
- Result: run-xpc ok; attach succeeded (pid_matches_service_pid true); sandbox_extension_consume hook installed; no sandbox-export-call events observed during sandbox_check probe.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/f20641ce-63e7-40b6-9d38-3659fcb1246a/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/f20641ce-63e7-40b6-9d38-3659fcb1246a/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/f20641ce-63e7-40b6-9d38-3659fcb1246a/frida/events.jsonl.
- Status: partial (hook installed without XPC error; no calls observed).
- Follow-up: try a dedicated extension issue/consume/release selftest to force calls.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id sandbox_check --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_release.json --no-prepare-selftest --probe-args --operation file-read-data --path /etc/hosts
- Result: run-xpc ok; attach succeeded (pid_matches_service_pid true); sandbox_extension_release hook installed; no sandbox-export-call events observed during sandbox_check probe.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/99e1a08e-f60e-49cf-a2b3-61b9d4d89b3a/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/99e1a08e-f60e-49cf-a2b3-61b9d4d89b3a/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/99e1a08e-f60e-49cf-a2b3-61b9d4d89b3a/frida/events.jsonl.
- Status: partial (hook installed without XPC error; no calls observed).
- Follow-up: try a dedicated extension issue/consume/release selftest to force calls.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable --ack-risk fully_injectable --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_extension_selftest.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_selftest.json
- Result: run-xpc ok; attach succeeded (pid_matches_service_pid true); sandbox_extension_selftest attempted sandbox_extension_issue_file for /etc/hosts with extension com.apple.app-sandbox.read; issue failed errno 1; no consume/release.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/3866d936-2c9b-4322-a361-60821ab25ae9/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/3866d936-2c9b-4322-a361-60821ab25ae9/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/3866d936-2c9b-4322-a361-60821ab25ae9/frida/events.jsonl.
- Status: partial (extension issue attempt captured; issuance blocked).
- Follow-up: try alternate extension classes or paths if a successful issuance witness is required.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable_extensions --ack-risk fully_injectable_extensions --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/smoke.js --probe-args --op create --path-class tmp --target specimen_file --name ej_extension.txt
- Result: run-xpc ok; file_path under entitlement-jail-harness/fs-op/<run_dir>/ej_extension.txt; follow-up check found the file missing (ENOENT), suggesting run_dir cleanup before extension issue.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/d5968de8-abeb-459f-9cc1-10bb4e997522/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/d5968de8-abeb-459f-9cc1-10bb4e997522/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/d5968de8-abeb-459f-9cc1-10bb4e997522/frida/events.jsonl.
- Status: partial (fs_op create ok; harness file not persistent across runs).
- Follow-up: avoid run_dir paths for extension issuance; use allow-unsafe paths or a persistent harness location.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable_extensions --ack-risk fully_injectable_extensions --probe-id sandbox_extension --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_issue_file.json --probe-args --op issue_file --class com.apple.app-sandbox.read --path /Users/achyland/Library/Containers/com.yourteam.entitlement-jail.ProbeService_fully_injectable_extensions/Data/tmp/entitlement-jail-harness/fs-op/17FFE3AC-7E23-4F47-88D1-E4274612F75E/ej_extension.txt
- Result: issue_failed (errno 2, No such file or directory); sandbox_export_isolation installed hook but no token returned.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/976bbb19-00f8-4590-b48f-062dae251f11/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/976bbb19-00f8-4590-b48f-062dae251f11/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/976bbb19-00f8-4590-b48f-062dae251f11/frida/events.jsonl.
- Status: partial (probe ran; harness path missing at issue time).
- Follow-up: use allow-unsafe path or a persistent file.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable_extensions --ack-risk fully_injectable_extensions --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/smoke.js --probe-args --op create --path-class tmp --target base --name ej_extension.txt
- Result: op_failed (errno 21, Is a directory); file_path resolves to tmp dir; --name ignored for target base.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/a26f236f-166c-4321-817c-a995f951a426/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/a26f236f-166c-4321-817c-a995f951a426/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/a26f236f-166c-4321-817c-a995f951a426/frida/events.jsonl.
- Status: blocked (target base does not accept name for create).
- Follow-up: use direct path with --allow-unsafe-path or a different target.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable_extensions --ack-risk fully_injectable_extensions --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/smoke.js --probe-args --op create --path-class tmp --target harness_dir --name ej_extension.txt
- Result: op_failed (errno 21, Is a directory); file_path resolves to harness_dir; --name ignored for target harness_dir.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/8a907c5b-79af-4e6e-9381-b1485c6dd6bf/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/8a907c5b-79af-4e6e-9381-b1485c6dd6bf/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/8a907c5b-79af-4e6e-9381-b1485c6dd6bf/frida/events.jsonl.
- Status: blocked (target harness_dir does not accept name for create).
- Follow-up: use direct path with --allow-unsafe-path or a different target.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable_extensions --ack-risk fully_injectable_extensions --probe-id sandbox_extension --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_issue_file.json --probe-args --op issue_file --class com.apple.app-sandbox.read --path /etc/hosts --allow-unsafe-path
- Result: run-xpc ok; token returned in stdout; sandbox_export_isolation captured sandbox_extension_issue_file call with args [com.apple.app-sandbox.read, /etc/hosts].
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/0bc59fb9-6ef6-448b-8fb2-29a403913b3e/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/0bc59fb9-6ef6-448b-8fb2-29a403913b3e/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/0bc59fb9-6ef6-448b-8fb2-29a403913b3e/frida/events.jsonl.
- Status: partial (issue succeeds; consume/release still failing).
- Follow-up: test consume/release token semantics.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id minimal --probe-id sandbox_extension --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_consume.json --probe-args --op consume --token 09902b0d559a762b7462af2cc6cf44908dbb1c9fb9fd47f42acf882467b52886
- Result: consume_failed (errno 22, Invalid argument); Frida attach denied (PermissionDeniedError).
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/9b94fb08-cf29-482f-ab86-dac6995b8801/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/9b94fb08-cf29-482f-ab86-dac6995b8801/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/9b94fb08-cf29-482f-ab86-dac6995b8801/frida/events.jsonl.
- Status: blocked (minimal profile not injectable; consume failed).
- Follow-up: retry with full token and/or fully_injectable_extensions to capture calls.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id minimal --probe-id sandbox_extension --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_consume.json --probe-args --op consume --token '09902b0d559a762b7462af2cc6cf44908dbb1c9fb9fd47f42acf882467b52886;00;00000000;00000000;00000000;000000000000001a;com.apple.app-sandbox.read;01;01000011;0000000004bce707;01;/private/etc/hosts'
- Result: consume_failed (errno 17, File exists); Frida attach denied (PermissionDeniedError).
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/3636ac13-d8f1-43c8-a2fb-e15ea5f7dab5/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/3636ac13-d8f1-43c8-a2fb-e15ea5f7dab5/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/3636ac13-d8f1-43c8-a2fb-e15ea5f7dab5/frida/events.jsonl.
- Status: blocked (minimal profile not injectable; consume failed).
- Follow-up: capture consume under fully_injectable_extensions to see return behavior.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id minimal --probe-id sandbox_extension --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_release.json --probe-args --op release --token '09902b0d559a762b7462af2cc6cf44908dbb1c9fb9fd47f42acf882467b52886;00;00000000;00000000;00000000;000000000000001a;com.apple.app-sandbox.read;01;01000011;0000000004bce707;01;/private/etc/hosts'
- Result: release_failed (errno 22, Invalid argument); Frida attach denied (PermissionDeniedError).
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/1d2adecd-8894-488a-96b7-5eedd27593ca/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/1d2adecd-8894-488a-96b7-5eedd27593ca/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/1d2adecd-8894-488a-96b7-5eedd27593ca/frida/events.jsonl.
- Status: blocked (minimal profile not injectable; release failed).
- Follow-up: retry release under fully_injectable_extensions.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable_extensions --ack-risk fully_injectable_extensions --probe-id sandbox_extension --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_consume.json --probe-args --op consume --token '09902b0d559a762b7462af2cc6cf44908dbb1c9fb9fd47f42acf882467b52886;00;00000000;00000000;00000000;000000000000001a;com.apple.app-sandbox.read;01;01000011;0000000004bce707;01;/private/etc/hosts'
- Result: consume_failed (errno 17, File exists); sandbox_export_isolation captured sandbox_extension_consume call (ret_i32 2).
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/15d6f3ec-da32-4fe9-a765-407c3990ac82/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/15d6f3ec-da32-4fe9-a765-407c3990ac82/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/15d6f3ec-da32-4fe9-a765-407c3990ac82/frida/events.jsonl.
- Status: partial (consume call captured; outcome still failing).
- Follow-up: determine whether EEXIST indicates token already consumed or path already allowed.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id fully_injectable_extensions --ack-risk fully_injectable_extensions --probe-id sandbox_extension --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_release.json --probe-args --op release --token '09902b0d559a762b7462af2cc6cf44908dbb1c9fb9fd47f42acf882467b52886;00;00000000;00000000;00000000;000000000000001a;com.apple.app-sandbox.read;01;01000011;0000000004bce707;01;/private/etc/hosts'
- Result: release_failed (errno 22, Invalid argument); sandbox_export_isolation captured sandbox_extension_release call (ret_i32 -1).
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/335f82f3-3a70-4070-818d-22a7d3bfe3cd/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/335f82f3-3a70-4070-818d-22a7d3bfe3cd/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/335f82f3-3a70-4070-818d-22a7d3bfe3cd/frida/events.jsonl.
- Status: partial (release call captured; outcome still failing).
- Follow-up: clarify token semantics with EntitlementJail maintainers.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id minimal@injectable --ack-risk minimal@injectable --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_selftest.js
- Result: command timed out in the harness after capabilities_snapshot; Frida hooks installed and self-open emitted errno 13, but no run_xpc/manifest emitted.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/7cf0b52b-e6a8-4b27-9503-180d4dc9ccd3/ej/capabilities_snapshot.json; book/experiments/runtime-final-final/suites/frida-testing/out/7cf0b52b-e6a8-4b27-9503-180d4dc9ccd3/ej/logs/capabilities_snapshot.log; book/experiments/runtime-final-final/suites/frida-testing/out/7cf0b52b-e6a8-4b27-9503-180d4dc9ccd3/ej/logs/observer/capabilities_snapshot.log.observer.json; book/experiments/runtime-final-final/suites/frida-testing/out/7cf0b52b-e6a8-4b27-9503-180d4dc9ccd3/frida/events.jsonl.
- Status: partial (harness timeout; session output missing).
- Follow-up: rerun with a longer timeout to capture run_xpc/manifest.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id minimal@injectable --ack-risk minimal@injectable --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_selftest.js
- Result: run-xpc session ok; attach succeeded with pid_matches_service_pid true; fs_open_selftest.js emitted fs-open errno 13; selftest path preparation failed with PermissionError.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/b03ad4a9-d2b3-438e-a71c-cab0ec92b0f3/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/b03ad4a9-d2b3-438e-a71c-cab0ec92b0f3/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/b03ad4a9-d2b3-438e-a71c-cab0ec92b0f3/ej/capabilities_snapshot.json; book/experiments/runtime-final-final/suites/frida-testing/out/b03ad4a9-d2b3-438e-a71c-cab0ec92b0f3/frida/events.jsonl; book/experiments/runtime-final-final/suites/frida-testing/out/b03ad4a9-d2b3-438e-a71c-cab0ec92b0f3/frida/meta.json.
- Status: ok (attach + probe_catalog succeeded).
- Follow-up: investigate why selftest path preparation failed under minimal@injectable.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id minimal@injectable --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/smoke.js --no-prepare-selftest
- Result: run-xpc ok; attach succeeded with pid_matches_service_pid true; wait/trigger events observed; selftest prep skipped.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/916d33bd-97fb-4cd1-9346-fe0c70faa542/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/916d33bd-97fb-4cd1-9346-fe0c70faa542/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/916d33bd-97fb-4cd1-9346-fe0c70faa542/frida/events.jsonl; book/experiments/runtime-final-final/suites/frida-testing/out/916d33bd-97fb-4cd1-9346-fe0c70faa542/frida/meta.json.
- Status: ok.
- Follow-up: use this as the attach-first baseline for minimal@injectable.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id <profile@injectable> --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/smoke.js --no-prepare-selftest (profiles: minimal, net_client, downloads_rw, user_selected_executable, bookmarks_app_scope, temporary_exception)
- Result: all six runs failed to open XPC session; run_xpc error NSCocoaErrorDomain Code 4099 (error 159 - Sandbox restriction); no session_ready, no Frida attach.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/994d18ad-9656-4c07-952a-3cdeb5b8a2af/manifest.json (minimal@injectable); book/experiments/runtime-final-final/suites/frida-testing/out/d30a92eb-4a42-49de-875d-747691edc42a/manifest.json (net_client@injectable); book/experiments/runtime-final-final/suites/frida-testing/out/e3c2b193-59c8-4cd1-82cd-9475aff52238/manifest.json (downloads_rw@injectable); book/experiments/runtime-final-final/suites/frida-testing/out/ad8a7d53-5e05-429e-995f-346a6068ef44/manifest.json (user_selected_executable@injectable); book/experiments/runtime-final-final/suites/frida-testing/out/f32fa4ed-9eef-48f0-a76e-cad99c5d27fc/manifest.json (bookmarks_app_scope@injectable); book/experiments/runtime-final-final/suites/frida-testing/out/bcf5e8b2-8c05-4932-93e0-61fdeb5ec42e/manifest.json (temporary_exception@injectable).
- Status: blocked (XPC connection invalidated).
- Follow-up: verify EntitlementJail XPC reachability for @injectable profiles before continuing sweep.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id temporary_exception@injectable --probe-id sandbox_extension --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_export_isolation.js --frida-config-path book/experiments/runtime-final-final/suites/frida-testing/out/inputs/sandbox_export_isolation/sandbox_extension_issue_file.json --no-prepare-selftest --probe-args --op issue_file --class com.apple.app-sandbox.read --path-class tmp --target specimen_file --name ej_extension.txt --create
- Result: XPC session not ready; run_xpc error NSCocoaErrorDomain Code 4099 (error 159 - Sandbox restriction); no token or Frida attach.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/a066da1c-a9c5-4879-b8b5-ee91f745bee8/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/a066da1c-a9c5-4879-b8b5-ee91f745bee8/ej/run_xpc.json.
- Status: blocked.
- Follow-up: resolve XPC connection issue before attempting consume/release.

- Command: book/tools/entitlement/EntitlementJail.app/Contents/MacOS/entitlement-jail xpc run --profile minimal@injectable probe_catalog
- Result: xpc_error with NSCocoaErrorDomain Code 4099 (error 159 - Sandbox restriction); no probe output.
- Artifacts: none (stdout-only JSON error).
- Status: blocked.
- Follow-up: confirm whether EntitlementJail requires a different launch or installation path for @injectable services.

- Command: book/tools/entitlement/EntitlementJail.app/Contents/MacOS/entitlement-jail health-check --profile minimal@injectable (elevated)
- Result: ok; capabilities_snapshot/world_shape/fs_op probes all returned normalized_outcome ok for minimal@injectable.
- Artifacts: stdout-only JSON health_check_report.
- Status: ok.
- Follow-up: use elevated runs for XPC sessions when the harness sandbox blocks lookups.

- Command: book/tools/entitlement/EntitlementJail.app/Contents/MacOS/entitlement-jail xpc run --profile minimal@injectable probe_catalog (elevated)
- Result: run ok; service_pid reported; probe_catalog JSON returned (high concern warning only).
- Artifacts: stdout-only JSON probe_response.
- Status: ok.
- Follow-up: rerun the @injectable sweep with elevated permissions.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id <profile@injectable> --probe-id probe_catalog --script book/experiments/runtime-final-final/suites/frida-testing/hooks/smoke.js --no-prepare-selftest (profiles: minimal, net_client, downloads_rw, user_selected_executable, bookmarks_app_scope, temporary_exception) (elevated)
- Result: all six runs succeeded; session_ready + probe_done recorded; Frida attach ok (pid_matches_service_pid true).
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/c474eb4e-57b9-4325-8e62-a140b4b14635/manifest.json (minimal@injectable); book/experiments/runtime-final-final/suites/frida-testing/out/49e69f56-c29b-492e-acf7-7c3e12827de8/manifest.json (net_client@injectable); book/experiments/runtime-final-final/suites/frida-testing/out/e3d62720-ce97-48b8-a243-62b1a067635e/manifest.json (downloads_rw@injectable); book/experiments/runtime-final-final/suites/frida-testing/out/9917a124-ce0e-4809-9d83-87bb8a10d731/manifest.json (user_selected_executable@injectable); book/experiments/runtime-final-final/suites/frida-testing/out/30c14e26-0f69-4d67-87e8-ca30cd01151a/manifest.json (bookmarks_app_scope@injectable); book/experiments/runtime-final-final/suites/frida-testing/out/2d0dc547-22af-4305-9ba8-fecf2bc48cc1/manifest.json (temporary_exception@injectable).
- Status: ok.
- Follow-up: treat harness-only XPC restrictions as a sandbox artifact; continue future runs with elevated permissions.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id minimal@injectable --probe-id fs_op --script book/experiments/runtime-final-final/suites/frida-testing/hooks/fs_open_selftest.js --no-prepare-selftest --probe-args --op open_read --path-class tmp --target specimen_file (elevated)
- Result: run-xpc ok; attach succeeded; fs_open_selftest self-open attempted in tmp/ej_noaccess; fs-open event captured (errno 13) with backtrace.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/1d996a72-4c75-4f43-bb71-639f445fd31d/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/1d996a72-4c75-4f43-bb71-639f445fd31d/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/1d996a72-4c75-4f43-bb71-639f445fd31d/frida/events.jsonl.
- Status: ok.
- Follow-up: use elevated runs for fs_open_selftest + fs_op when the harness sandbox blocks XPC sessions.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id minimal@injectable --probe-id sandbox_check --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_check_trace.js --no-prepare-selftest --probe-args --operation file-read-data --path /etc/hosts (elevated)
- Result: run-xpc ok; attach succeeded; hook candidates count 36; sandbox_check call observed with args ["file-read-data", "/etc/hosts"] and ret_i32 1.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/265ebd80-5536-444d-aaf3-dea3cdf7bb16/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/265ebd80-5536-444d-aaf3-dea3cdf7bb16/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/265ebd80-5536-444d-aaf3-dea3cdf7bb16/frida/events.jsonl.
- Status: ok.
- Follow-up: treat sandbox_check_trace as unblocked when running outside the harness sandbox.

- Command: ./.venv/bin/python book/experiments/runtime-final-final/suites/frida-testing/run_ej_frida.py --profile-id minimal@injectable --probe-id sandbox_check --script book/experiments/runtime-final-final/suites/frida-testing/hooks/sandbox_check_minimal.js --no-prepare-selftest --probe-args --operation file-read-data --path /etc/hosts (elevated)
- Result: run-xpc ok; attach succeeded; hook candidates count 2; sandbox_check call observed with args ["file-read-data"] and ret_i32 1.
- Artifacts: book/experiments/runtime-final-final/suites/frida-testing/out/ecb71fb6-3213-4285-978d-33583472ccbd/manifest.json; book/experiments/runtime-final-final/suites/frida-testing/out/ecb71fb6-3213-4285-978d-33583472ccbd/ej/run_xpc.json; book/experiments/runtime-final-final/suites/frida-testing/out/ecb71fb6-3213-4285-978d-33583472ccbd/frida/events.jsonl.
- Status: ok.
- Follow-up: use this minimal hook to avoid broader sandbox symbol interception when stability is required.

## Entry template
- Command:
- Result:
- Artifacts:
- Status:
- Follow-up:
