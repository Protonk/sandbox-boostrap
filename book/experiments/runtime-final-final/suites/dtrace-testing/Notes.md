# dtrace-testing notes

## Entitlements capture
- `codesign -d --entitlements :- --xml --verbose=4` reports an invalid entitlements blob and emits no entitlements; saved in `out/entitlements/EntitlementJail.app.entitlements.txt` and `out/entitlements/ProbeService_debuggable.xpc.entitlements.txt`.
- `strings` scan of `ProbeService_debuggable` shows `com.apple.security.get-task-allow` and `com.apple.security.cs.disable-library-validation`; saved in `out/entitlements/ProbeService_debuggable.entitlements.strings.txt` (brittle witness).
- `capabilities_snapshot` output for `ProbeService_debuggable` saved in `out/entitlements/ProbeService_debuggable.capabilities_snapshot*.json` shows `has_get_task_allow=true` and `has_disable_library_validation=true` (runtime witness).

## Target PID selection
- `pgrep` failed because sysmond is missing; `ps` required escalated access.
- PID selection is taken from `capabilities_snapshot.details.service_pid` with process_name `ProbeService_debuggable`.
- Consecutive `run-xpc` calls yielded different `service_pid` values (service is short-lived per run).

## DTrace runs
- `capture.py` smoke/idle/interaction attempts wrote raw JSONL files, but DTrace stderr reported SIP enabled and missing privileges.
- `sudo -n /usr/sbin/dtrace -V` failed due to password requirement.
- Re-tried smoke capture with a fresh `service_pid` from `capabilities_snapshot`; DTrace still failed to initialize without additional privileges.
- User rerun with sudo and a two-terminal attach flow; DTrace reported `failed to grab pid <pid>`, leaving `smoke.jsonl` empty. Root cause still unknown (pid lifetime vs attach permissions).
- Control test: `sudo /usr/sbin/dtrace -p <pid> -n 'syscall::getpid:entry { }'` against `sleep 10` also failed with `failed to grab pid <pid>`. This suggests PID attach is blocked on this host even for a trivial process (blocked).
- Non-system target attempt: built `book/experiments/runtime-final-final/suites/dtrace-testing/targets/sleep_loop` and attached via `dtrace -p` without sudo; stderr reported `DTrace requires additional privileges` and no events were captured. Stderr saved in `out/meta/dtrace_non_system.stderr`.
- Non-system target sudo attempt (non-interactive): `sudo -n dtrace -p <sleep_loop_pid>` failed with `sudo: a password is required`; stderr saved in `out/meta/dtrace_non_system_sudo.stderr` and meta in `out/meta/dtrace_non_system_sudo.json` (blocked by harness auth).
- Non-system target sudo attempt (interactive) reached DTrace but failed with `invalid probe specifier syscall::nanosleep:entry ... System Integrity Protection is on`; stdout empty. Stderr in `out/meta/dtrace_non_system_sudo.stderr`.
- Regenerated `out/meta/dtrace_non_system_sudo.json` with the captured `sleep_loop` PID and exit code (pid is ephemeral; the key point is that the PID used for `-p` matches the `sleep_loop` process).

## Interaction sequence
- Ran `run-xpc` fs_op sequence against `ProbeService_debuggable`:
  - `stat` with `--path-class downloads` (ok)
  - `open_read` with `--path-class downloads` (permission_error, errno 1)
  - `listdir` with `--path-class downloads` (permission_error, errno 1)
- Outputs saved in `out/interaction/fs_op_{stat,open_read,listdir}.json`.

## Normalization
- `normalize.py` emitted `out/normalized/deny_signatures.json` with zero events because DTrace capture failed.
