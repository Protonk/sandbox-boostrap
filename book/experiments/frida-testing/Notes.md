# frida-testing Notes

## Running log
- Command: cc -O0 -g -o book/experiments/frida-testing/targets/open_loop book/experiments/frida-testing/targets/open_loop.c
- Result: built the bootstrap target binary.
- Artifacts: `book/experiments/frida-testing/targets/open_loop`
- Status: ok
- Follow-up: run `book/experiments/frida-testing/run_frida.py` with a hook and capture the first JSONL output.

- Command: ./.venv/bin/python -c 'import sys,frida; print("py:",sys.executable); print("frida:",frida.__version__)'
- Result: confirmed venv Python and frida 17.5.2.
- Artifacts: none
- Status: ok
- Follow-up: run fs_open hook with a deterministic EACCES target.

- Command: ./.venv/bin/python book/experiments/frida-testing/run_frida.py --spawn book/experiments/frida-testing/targets/open_loop /tmp/frida_testing_noaccess --script book/experiments/frida-testing/hooks/fs_open.js --duration-s 2
- Result: runner terminated with exit code 139; events.jsonl empty.
- Artifacts: `book/experiments/frida-testing/out/04968c5a-ab8b-45d9-8d41-84f11f223d64`
- Status: blocked (signal 11 before any send() payloads)
- Follow-up: stabilize runner/hook so spawn captures fs-open events with errno.

- Command: ./.venv/bin/python book/experiments/frida-testing/run_frida.py --spawn book/experiments/frida-testing/targets/open_loop /etc/hosts --script book/experiments/frida-testing/hooks/discover_sandbox_exports.js --duration-s 1
- Result: runner terminated with signal 11 (Sandbox(Signal(11))); events.jsonl empty.
- Artifacts: `book/experiments/frida-testing/out/64dfc33f-3275-4656-94c3-a427dd129a95`
- Status: blocked (signal 11 before any send() payloads)
- Follow-up: stabilize runner/hook so export inventory is emitted.

- Command: uname -m; file ./.venv/bin/python; ./.venv/bin/python -c 'import platform,sys; print("machine:", platform.machine()); print("exe:", sys.executable)'; file book/experiments/frida-testing/targets/open_loop; file book/tools/entitlement/EntitlementJail.app/Contents/MacOS/entitlement-jail
- Result: host, venv Python, open_loop, and entitlement-jail are all arm64 (no Rosetta mismatch).
- Artifacts: none
- Status: ok
- Follow-up: proceed with attach-first tests.

- Command: sed -n '1,120p' ~/Library/Logs/DiagnosticReports/Python-2025-12-22-161938.ips
- Result: Process=Python; Parent=zsh; Termination=SIGNAL 11 (Segmentation fault); Exception Type=EXC_BAD_ACCESS (SIGSEGV); faulting thread includes frida-main-loop.
- Artifacts: ~/Library/Logs/DiagnosticReports/Python-2025-12-22-161938.ips
- Status: ok
- Follow-up: treat spawn as unstable; pivot to attach-first.

- Command: book/tools/entitlement/EntitlementJail.app/Contents/MacOS/entitlement-jail run-system /bin/sleep 30 (background) + ./.venv/bin/python book/experiments/frida-testing/run_frida.py --attach-pid <pid> --script book/experiments/frida-testing/hooks/smoke.js --duration-s 2
- Result: ProcessNotRespondingError (refused to load frida-agent or terminated during injection); events.jsonl contains runner-exception.
- Artifacts: `book/experiments/frida-testing/out/5b0825cf-b3be-4a24-9a98-37fd4da5cb2f`
- Status: blocked (attach failed before any send() payloads)
- Follow-up: review helper/target crash reports; verify if CLI attach behaves differently.

- Command: sed -n '1,120p' ~/Library/Logs/DiagnosticReports/frida-helper-2025-12-22-170859.ips
- Result: Process=frida-helper; Parent=Python; Termination=SIGNAL 4 (Illegal instruction); Exception Type=EXC_BAD_ACCESS (SIGILL).
- Artifacts: ~/Library/Logs/DiagnosticReports/frida-helper-2025-12-22-170859.ips
- Status: ok
- Follow-up: treat as Frida helper-layer crash during attach.

- Command: sed -n '1,120p' ~/Library/Logs/DiagnosticReports/entitlement-jail-2025-12-22-170900.ips
- Result: Process=entitlement-jail; Parent=zsh; Termination=CODESIGNING Invalid Page (SIGKILL Code Signature Invalid); Exception Type=EXC_BAD_ACCESS.
- Artifacts: ~/Library/Logs/DiagnosticReports/entitlement-jail-2025-12-22-170900.ips
- Status: ok
- Follow-up: record as target crash during attach.

- Command: ./.venv/bin/python -c 'import frida; d=frida.get_local_device(); print(d)'
- Result: when run outside the Codex harness sandbox, prints `Device(id="local", ...)`; inside the harness sandbox this call can SIGSEGV, so frida-testing runs must be executed from a normal Terminal session (or otherwise outside the harness sandbox) to avoid misleading “plumbing” crashes.
- Artifacts: none
- Status: ok
- Follow-up: keep runs attach-first and outside harness sandbox.

- Command: book/experiments/frida-testing/targets/open_loop /etc/hosts (background) + ./.venv/bin/python book/experiments/frida-testing/run_frida.py --attach-pid <pid> --script book/experiments/frida-testing/hooks/smoke.js --duration-s 2
- Result: attach works; events.jsonl contains a `send` payload with `kind=smoke`.
- Artifacts: `book/experiments/frida-testing/out/0bd798d6-5986-4a26-a19c-28f7d577f240`
- Status: ok
- Follow-up: use the same attach target for export inventory and fs_open.

- Command: book/experiments/frida-testing/targets/open_loop /etc/hosts (background) + ./.venv/bin/python book/experiments/frida-testing/run_frida.py --attach-pid <pid> --script book/experiments/frida-testing/hooks/discover_sandbox_exports.js --duration-s 1
- Result: emits `kind=exports` with `module=libsystem_sandbox.dylib` and `count=87`.
- Artifacts: `book/experiments/frida-testing/out/903d8465-79c3-4ddf-ab01-83892c4a409c`
- Status: ok
- Follow-up: treat as an export-inventory witness only (no semantic claims).

- Command: DENY=/tmp/frida_testing_noaccess; chmod 000 "$DENY"; book/experiments/frida-testing/targets/open_loop "$DENY" (background) + ./.venv/bin/python book/experiments/frida-testing/run_frida.py --attach-pid <pid> --script book/experiments/frida-testing/hooks/fs_open.js --duration-s 2
- Result: emits repeated `kind=fs-open` events with `errno=13` (EACCES) for the deny path; this is an errno witness, not a sandbox attribution.
- Artifacts: `book/experiments/frida-testing/out/4f161bec-6ef0-4614-b070-58e9596f03a2`
- Status: ok
- Follow-up: keep this deny-path pattern for validating future hook packs.

- Command: EJ=book/tools/entitlement/EntitlementJail.app/Contents/MacOS/entitlement-jail; mkfifo $HOME/Library/Containers/com.yourteam.entitlement-jail.ProbeService_debuggable/Data/tmp/frida_hold_fifo; entitlement-jail run-xpc com.yourteam.entitlement-jail.ProbeService_debuggable fs_op --op open_read --path <fifo> --allow-unsafe-path (background) + pgrep -x ProbeService_debuggable + ./.venv/bin/python book/experiments/frida-testing/run_frida.py --attach-pid <pid> --script book/experiments/frida-testing/hooks/smoke.js --duration-s 2
- Result: run-xpc reported NSCocoaErrorDomain Code 4097 (connection to service failed); frida attach raised ProcessNotRespondingError; events.jsonl contains only runner events.
- Artifacts: `book/experiments/frida-testing/out/6bf9e68e-1984-410d-9c9d-bc7b4a0023b8`; ~/Library/Logs/DiagnosticReports/ProbeService_debuggable-2025-12-22-222958.ips; ~/Library/Logs/DiagnosticReports/frida-helper-2025-12-22-222957.ips
- Status: blocked (target killed with CODESIGNING Invalid Page; frida-helper SIGILL)
- Follow-up: treat as attach failure on the debug XPC service and consider other EntitlementJail service variants or alternate attach orchestration.

- Command: codesign -d --entitlements :- EntitlementJail XPC targets (debuggable, fully_injectable)
- Result: `ProbeService_fully_injectable` now includes `com.apple.security.get-task-allow` along with `disable-library-validation`, `allow-dyld-environment-variables`, `allow-jit`, and `allow-unsigned-executable-memory`.
- Artifacts: none
- Status: ok
- Follow-up: target fully_injectable for attach-first attempts.

- Command: entitlement-jail run-xpc --hold-open 15 com.yourteam.entitlement-jail.ProbeService_fully_injectable probe_catalog (background) + pgrep -x ProbeService_fully_injectable + ./.venv/bin/python book/experiments/frida-testing/run_frida.py --attach-pid <pid> --script book/experiments/frida-testing/hooks/smoke.js --duration-s 2
- Result: attach succeeded; smoke payload emitted.
- Artifacts: `book/experiments/frida-testing/out/539ea0e4-fd01-4b23-b698-17e5256afc3f`
- Status: ok
- Follow-up: use the same target for export inventory and fs_open attempts.

- Command: entitlement-jail run-xpc --hold-open 15 com.yourteam.entitlement-jail.ProbeService_fully_injectable probe_catalog (background) + pgrep -x ProbeService_fully_injectable + ./.venv/bin/python book/experiments/frida-testing/run_frida.py --attach-pid <pid> --script book/experiments/frida-testing/hooks/discover_sandbox_exports.js --duration-s 2
- Result: emits `kind=exports` with module `libsystem_sandbox.dylib`, count `87`, and the expected sandbox_* symbol list.
- Artifacts: `book/experiments/frida-testing/out/9fc56e61-bd29-4e04-b2a8-c3497114d624`
- Status: ok
- Follow-up: treat as export-inventory witness only.

- Command: entitlement-jail run-xpc --hold-open 20 com.yourteam.entitlement-jail.ProbeService_fully_injectable probe_catalog (background) + attach fs_open to that PID + entitlement-jail run-xpc com.yourteam.entitlement-jail.ProbeService_fully_injectable fs_op --op open_read --path <container tmp/ej_noaccess> --allow-unsafe-path
- Result: frida hook installed but no `fs-open` events; fs_op executed in a different PID than the attached service (fs_op log shows `service_pid` 56652 vs attach PID 56639), so no open call observed in the hooked process.
- Artifacts: `book/experiments/frida-testing/out/c014afa1-e042-4373-a69a-510be8632aca`; /tmp/ej_fs_op_fully_injectable.log
- Status: partial (hooking works; fs_op open ran in a different process)
- Follow-up: find an attach orchestration that keeps probe execution in the same XPC service PID.

- Command: entitlement-jail run-xpc --hold-open 15 com.yourteam.entitlement-jail.ProbeService_debuggable probe_catalog (background) + pgrep -x ProbeService_debuggable + ./.venv/bin/python book/experiments/frida-testing/run_frida.py --attach-pid <pid> --script book/experiments/frida-testing/hooks/smoke.js --duration-s 2
- Result: ProcessNotRespondingError; debug service killed with CODESIGNING Invalid Page and frida-helper crashed (SIGILL).
- Artifacts: `book/experiments/frida-testing/out/fadc03b3-eaf8-4b4c-a8e0-176f476a31ce`; ~/Library/Logs/DiagnosticReports/ProbeService_debuggable-2025-12-23-085838.ips; ~/Library/Logs/DiagnosticReports/frida-helper-2025-12-23-085837.ips
- Status: blocked
- Follow-up: keep `ProbeService_fully_injectable` as the attach-first target; treat `ProbeService_debuggable` as currently non-attachable.

- Command: add `book/experiments/frida-testing/hooks/fs_open_selftest.js` and update it to resolve a base path via getcwd for deterministic self-open.
- Result: new self-open hook that attempts an open after attach and emits `self-open` + `fs-open` payloads.
- Artifacts: `book/experiments/frida-testing/hooks/fs_open_selftest.js`
- Status: ok
- Follow-up: run against `ProbeService_fully_injectable` with a deterministic deny path.

- Command: entitlement-jail run-xpc --hold-open 15 com.yourteam.entitlement-jail.ProbeService_fully_injectable probe_catalog (background) + pgrep -x ProbeService_fully_injectable + ./.venv/bin/python book/experiments/frida-testing/run_frida.py --attach-pid <pid> --script book/experiments/frida-testing/hooks/smoke.js --duration-s 2
- Result: attach succeeded; smoke payload emitted.
- Artifacts: `book/experiments/frida-testing/out/6d8f44e4-1fa0-4f99-bab6-bb13f6858257`
- Status: ok
- Follow-up: run export inventory on the same target.

- Command: entitlement-jail run-xpc --hold-open 15 com.yourteam.entitlement-jail.ProbeService_fully_injectable probe_catalog (background) + pgrep -x ProbeService_fully_injectable + ./.venv/bin/python book/experiments/frida-testing/run_frida.py --attach-pid <pid> --script book/experiments/frida-testing/hooks/discover_sandbox_exports.js --duration-s 2
- Result: emits `kind=exports` with module `libsystem_sandbox.dylib`, count `87`, and sandbox_* symbols.
- Artifacts: `book/experiments/frida-testing/out/673e5a1e-1fab-4010-a74e-9a91b217f830`
- Status: ok
- Follow-up: run fs_open self-open witness.

- Command: entitlement-jail run-xpc --hold-open 20 com.yourteam.entitlement-jail.ProbeService_fully_injectable probe_catalog (background) + attach fs_open_selftest.js (initial version) + create /tmp/ej_noaccess
- Result: `self-open` targeted /tmp; `fs-open` emitted errno 2 (ENOENT) due to missing path in the target context.
- Artifacts: `book/experiments/frida-testing/out/8c03be0d-465d-450b-a680-2d4860d1dc94`
- Status: partial
- Follow-up: update fs_open_selftest.js to derive a container path and rerun.

- Command: entitlement-jail run-xpc --hold-open 20 com.yourteam.entitlement-jail.ProbeService_fully_injectable probe_catalog (background) + attach fs_open_selftest.js + create container tmp/ej_noaccess with chmod 000
- Result: emits `self-open` + `fs-open` with errno 13 (EACCES) against the container tmp path.
- Artifacts: `book/experiments/frida-testing/out/56577123-16b4-4335-be63-3478e63a7c88`
- Status: ok
- Follow-up: keep fs_open_selftest for deterministic errno witnesses until an in-process `fs_op_wait` exists.

- Command: entitlement-jail run-xpc --attach 30 --hold-open 30 com.yourteam.entitlement-jail.ProbeService_fully_injectable fs_op --op open_read --path-class tmp --name ej_noaccess (background; capture wait-ready path) + create ej_noaccess file in the wait path dir + ./.venv/bin/python book/experiments/frida-testing/run_frida.py --attach-pid <pid> --script book/experiments/frida-testing/hooks/fs_open.js --duration-s 5 + echo go > wait FIFO
- Result: attach wait flow worked; run-xpc reported wait metadata (`wait_*` fields) and completed with normalized_outcome ok; fs_open hook installed but no fs-open events (open succeeded in harness path).
- Artifacts: `book/experiments/frida-testing/out/cb34ec8c-6798-4811-9793-9b4c99efe912`; /tmp/ej_attach_wait.log; /tmp/ej_attach_out.log
- Status: ok (attach + wait path validated)
- Follow-up: use `--attach` with a direct path or `--allow-unsafe-path` if we need deterministic errno events from fs_op.

- Command: entitlement-jail run-xpc com.yourteam.entitlement-jail.ProbeService_fully_injectable capabilities_snapshot
- Result: captured containerized `tmp_dir` and entitlement flags for the fully_injectable service.
- Artifacts: /tmp/ej_caps_snapshot.json
- Status: ok
- Follow-up: use the container tmp path for direct-path fs_op probes.

- Command: entitlement-jail run-xpc --attach 30 --hold-open 30 com.yourteam.entitlement-jail.ProbeService_fully_injectable fs_op --op open_read --path <container tmp>/ej_noaccess --allow-unsafe-path (background; capture wait-ready path) + chmod 000 ej_noaccess + ./.venv/bin/python book/experiments/frida-testing/run_frida.py --attach-pid <pid> --script book/experiments/frida-testing/hooks/fs_open.js --duration-s 5 + echo go > wait FIFO
- Result: run-xpc reported errno 13 with permission_error; fs_open hook installed but no fs-open events observed.
- Artifacts: `book/experiments/frida-testing/out/690fb15e-6664-48eb-8031-54d6068f3206`; /tmp/ej_attach_wait2.log; /tmp/ej_attach_out2.log
- Status: partial (fs_op errno witnessed; Frida hook did not see open)
- Follow-up: extend fs_open hook coverage and retry.

- Command: extend fs_open hook to include open$NOCANCEL, openat$NOCANCEL, __open, __open_nocancel, __openat, __openat_nocancel, then rerun the attach-wait fs_op direct-path probe
- Result: fs_open still observed only hook-installed events (no fs-open payloads) while fs_op returned errno 13.
- Artifacts: `book/experiments/frida-testing/out/bb6437a1-e7d8-4734-a4ee-a857b3762208`; /tmp/ej_attach_wait4.log; /tmp/ej_attach_out4.log
- Status: partial (fs_op errno witnessed; Frida hook still missing the open path)
- Follow-up: consider hooking open_dprotected_np/openat_dprotected_np or intercepting syscall-level open/openat.

- Command: extracted Frida runner core into `book/api/frida/runner.py` and updated `book/experiments/frida-testing/run_frida.py` to call it.
- Result: CLI wrapper now delegates to the API runner while preserving the meta.json + events.jsonl schema.
- Artifacts: `book/api/frida/runner.py`; `book/experiments/frida-testing/run_frida.py`
- Status: ok
- Follow-up: keep runner changes in the API layer for future promotion to `book/api/frida`.

- Command: attach `book/experiments/frida-testing/hooks/interceptor_selftest.js` to `ProbeService_fully_injectable` (initial version).
- Result: script error `TypeError: not a function` due to missing `Process.enumerateEnvironment`.
- Artifacts: `book/experiments/frida-testing/out/9bf3d548-783e-4d67-9ded-0699d2ec4050`
- Status: blocked (script error before selftest emitted results)
- Follow-up: guard `Process.enumerateEnvironment` and rerun.

- Command: attach `book/experiments/frida-testing/hooks/interceptor_selftest.js` (guarded) to `ProbeService_fully_injectable`.
- Result: hook installed and fired; selftest `open("/tmp/frida_testing_noaccess")` returned errno 2 (ENOENT).
- Artifacts: `book/experiments/frida-testing/out/cdbf72da-d118-4875-babb-1498bc770e4a`
- Status: ok (Interceptor works in-process)
- Follow-up: use funnel hooks to discover the real fs_op open path.

- Command: attach `book/experiments/frida-testing/hooks/fs_open_funnel.js` to `ProbeService_fully_injectable` during fs_op runs.
- Result: funnel enumerated open/openat exports and installed hooks; no `funnel-hit` events observed (including the syscall-expanded run).
- Artifacts: `book/experiments/frida-testing/out/c5b2484c-3e8d-4f26-9074-f59742f45e20`; `book/experiments/frida-testing/out/75b513c6-b674-4a04-8988-3cdc87874958`
- Status: partial (Interceptor works, but fs_op path still not observed)
- Follow-up: broaden funnel beyond libsystem_kernel and correlate with fs_op in the same PID.

- Command: add `book/experiments/frida-testing/hooks/sandbox_trace.js` and `book/experiments/frida-testing/parse_sandbox_trace.py` for sandbox trace gating.
- Result: new hook sets trace path and emits a single `sandbox-trace` payload; parser emits a JSON summary for the trace file (or a missing-trace witness).
- Artifacts: `book/experiments/frida-testing/hooks/sandbox_trace.js`; `book/experiments/frida-testing/parse_sandbox_trace.py`
- Status: ok
- Follow-up: run sandbox_trace during fs_op and capture summary output.

- Command: attach `sandbox_trace.js` to `ProbeService_fully_injectable` during fs_op (initial version).
- Result: script error `TypeError: not a function` from `Module.findExportByName`.
- Artifacts: `book/experiments/frida-testing/out/18ef5758-937a-4e9c-b54d-db999d23a270`
- Status: blocked (script error)
- Follow-up: add a fallback to `Module.getExportByName` and rerun.

- Command: attach `sandbox_trace.js` (with export lookup fallback) to `ProbeService_fully_injectable` during fs_op, then parse the trace file.
- Result: `sandbox_set_trace_path` reported missing in `libsystem_sandbox.dylib`; trace summary reports `trace_exists=false`.
- Artifacts: `book/experiments/frida-testing/out/227d3232-9da5-463d-bab4-2f7bbbfc03ae`; `book/experiments/frida-testing/out/227d3232-9da5-463d-bab4-2f7bbbfc03ae/sandbox_trace_summary.json`
- Status: partial (trace hook runs but trace path unavailable)
- Follow-up: decide whether to load a different module or target for sandbox trace gating.

- Command: attach the expanded file-decision funnel to `ProbeService_fully_injectable` during fs_op.
- Result: funnel hits observed for `__open` and `open` with errno 13 on the deny path.
- Artifacts: `book/experiments/frida-testing/out/0ee1b6e3-f000-4037-aaee-23ce3e7f0098`
- Status: ok
- Follow-up: update curated hooks to target `__open` and confirm with repeatable fs_op runs.

- Command: update `sandbox_trace.js` to a capability ladder (set_trace, vtrace, unavailable) and add unified-log capture helpers.
- Result: sandbox_trace now emits capability records and cleanly reports unavailability; added scripts for sandbox log capture + summary.
- Artifacts: `book/experiments/frida-testing/hooks/sandbox_trace.js`; `book/experiments/frida-testing/capture_sandbox_log.py`; `book/experiments/frida-testing/parse_sandbox_log.py`
- Status: ok
- Follow-up: run sandbox log capture alongside fs_op if in-process trace remains unavailable.

- Command: attach updated `sandbox_trace.js` to `ProbeService_fully_injectable` during fs_op.
- Result: capability record shows set_trace and vtrace functions missing; trace reported unavailable.
- Artifacts: `book/experiments/frida-testing/out/218aba7d-9290-4955-b82a-11b40266be0f`
- Status: partial (capability witness only; no in-process trace)
- Follow-up: use unified log capture as the fallback trace source.

- Command: attach minimal `fs_open.js` to `ProbeService_fully_injectable` during fs_op (deny path).
- Result: `fs-open` events observed for `__open` and `open` with errno 13.
- Artifacts: `book/experiments/frida-testing/out/797832ba-a22c-41ba-8f2a-370f87f97713`
- Status: ok
- Follow-up: keep minimal fs_open pack as the stable hook for fs_op observability.

- Command: run unified log capture alongside fs_op (deny-only + PID filter) while attaching minimal fs_open.
- Result: log capture produced only the header line; summary reports `parsed_lines=0` and `deny_events=0`; fs_open run recorded hook installs but no fs-open events in this attempt.
- Artifacts: `book/experiments/frida-testing/out/29f6de6c-7972-40ff-84e0-8b4a3e46c5b9/sandbox_log.ndjson`; `book/experiments/frida-testing/out/29f6de6c-7972-40ff-84e0-8b4a3e46c5b9/sandbox_log_meta.json`; `book/experiments/frida-testing/out/29f6de6c-7972-40ff-84e0-8b4a3e46c5b9/sandbox_log_summary.json`
- Status: partial (fallback capture produced no parsed deny events)
- Follow-up: consider a broader predicate if we need a non-empty deny stream.

- Command: update `capture_sandbox_log.py` to support ndjson output, log levels, colors, timeouts, and optional predicates.
- Result: capture helper now supports predicate-free sanity runs and broader capture settings.
- Artifacts: `book/experiments/frida-testing/capture_sandbox_log.py`
- Status: ok
- Follow-up: run no-predicate sanity capture to validate parse pipeline.

- Command: run unified-log capture with no predicate (sanity run) and parse output.
- Result: `parsed_lines=5449` confirms NDJSON capture and parsing are working.
- Artifacts: `book/experiments/frida-testing/out/8c89469f-5489-4285-b34e-a54e871625e5/sandbox_log.ndjson`; `book/experiments/frida-testing/out/8c89469f-5489-4285-b34e-a54e871625e5/sandbox_log_summary.json`
- Status: ok
- Follow-up: tighten predicates with sandbox-broad filters.

- Command: run sandbox-broad unified-log capture (kernel + Sandbox sender) alongside fs_op with minimal fs_open hooks.
- Result: parsed_lines nonzero (11) but no deny events; fs_open emitted events for `__open` and `open`.
- Artifacts: `book/experiments/frida-testing/out/c956e438-fd59-4ed1-b8b7-685b7e7f2747/sandbox_log.ndjson`; `book/experiments/frida-testing/out/c956e438-fd59-4ed1-b8b7-685b7e7f2747/sandbox_log_summary.json`
- Status: partial (capture works but denies not present under this predicate)
- Follow-up: try deny-focused predicate or alternative correlation filters.

- Command: run deny-focused unified-log capture (kernel + Sandbox sender + deny) alongside fs_op with minimal fs_open hooks.
- Result: header-only capture; parsed_lines 0; fs_open emitted events for `__open` and `open`.
- Artifacts: `book/experiments/frida-testing/out/b968dd05-c5f1-40c2-a8b1-f462711a3a78/sandbox_log.ndjson`; `book/experiments/frida-testing/out/b968dd05-c5f1-40c2-a8b1-f462711a3a78/sandbox_log_summary.json`
- Status: partial (deny-focused predicate too strict)
- Follow-up: use broader predicate or correlate via eventMessage text.

- Command: unified-log sanity run with no predicate using the updated capture helper.
- Result: parsed_lines=3980 confirms capture pipeline works (no predicate).
- Artifacts: `book/experiments/frida-testing/out/a987670e-67a4-458b-9e4a-8254e5e2ddcb/sandbox_log_summary.json`
- Status: ok
- Follow-up: proceed with sandbox-broad and deny-focused predicates.

- Command: fs_op on `~/Documents/frida_sandbox_deny.txt` (644) with sandbox-broad predicate + service-name correlation.
- Result: fs_op returned errno 1 (operation not permitted); frida attach failed with helper exited (status 9); log summary parsed_lines=1 (header only).
- Artifacts: `book/experiments/frida-testing/out/404b099b-6158-4278-8088-c8e191dd3ce7/sandbox_log_summary.json`
- Status: partial (attach failure; capture header only)
- Follow-up: rerun with the same predicate and confirm frida attach succeeds.

- Command: rerun sandbox-broad predicate with service-name correlation during fs_op on `~/Documents/frida_sandbox_deny.txt`.
- Result: fs_open emitted events for `__open` and `open` with errno 1; log summary parsed_lines=0 (header only).
- Artifacts: `book/experiments/frida-testing/out/a4c207ff-e0a9-43b1-ad70-18435bca2276/sandbox_log_summary.json`
- Status: partial (capture header only)
- Follow-up: try deny-focused predicate or root-level capture.

- Command: deny-focused predicate with service-name correlation during fs_op on `~/Documents/frida_sandbox_deny.txt`.
- Result: fs_open hook installed but no fs-open events; log summary parsed_lines=0 (header only).
- Artifacts: `book/experiments/frida-testing/out/f5c538d6-89b0-4a92-9115-31229ce5252a/sandbox_log_summary.json`
- Status: partial (deny-focused capture too strict, and no fs-open events in this run)
- Follow-up: broaden predicate or add explicit self-open inside the attached window.

- Command: attempt sudo log stream for unified log capture.
- Result: blocked by harness policy (no escalation permitted).
- Artifacts: none
- Status: blocked
- Follow-up: run sudo log capture outside the harness if root-level visibility is required.

## Entry template
- Command:
- Result:
- Artifacts:
- Status:
- Follow-up:
