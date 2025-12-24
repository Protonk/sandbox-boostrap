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

## Entry template
- Command:
- Result:
- Artifacts:
- Status:
- Follow-up:
