# dtrace-testing

## Purpose
Probe EntitlementJail’s runtime behavior with a SIP-compatible, PID-scoped DTrace program, capturing syscall denials and (when available) libsystem_sandbox API usage. The goal is to produce host-bound, JSONL raw traces and normalized deny signatures without upgrading runtime evidence to PolicyGraph semantics.

## Baseline & scope
- world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (`book/world/sonoma-14.4.1-23E224-arm64/world.json`)
- Host: macOS 14.4.1 (23E224), kernel 23.4.0, arm64, SIP enabled.
- Scope: syscall + pid providers only; filter to `pid == $target` and `errno == EPERM || errno == EACCES`.
- Target: EntitlementJail debug XPC service `ProbeService_debuggable` (process name `ProbeService_debuggable`).
- Out of scope: fbt/kperf probes, cross-version claims, mapping promotion.

## Deliverables / expected outcomes
- DTrace capture helper: `book/experiments/dtrace-testing/capture.py`.
- Normalization helper: `book/experiments/dtrace-testing/normalize.py`.
- Raw JSONL traces per phase in `book/experiments/dtrace-testing/out/raw/`.
- Phase-keyed deny signatures in `book/experiments/dtrace-testing/out/normalized/deny_signatures.json`.
- Entitlements witness artifacts in `book/experiments/dtrace-testing/out/entitlements/`.

## Plan & execution log
- Completed: entitlements extraction attempts via `codesign` (invalid entitlements blob reported; no entitlements emitted).
- Completed: runtime `capabilities_snapshot` outputs captured for `ProbeService_debuggable` (includes entitlement booleans and `service_pid`).
- Attempted: DTrace capture for smoke/idle/interaction; blocked by SIP privilege requirements (raw JSONL empty; stderr captured).
- Completed: repeatable interaction sequence via `fs_op` (stat/open_read/listdir against downloads path-class).

## Evidence & artifacts
- Entitlements (codesign warnings; no blob emitted):
  - `book/experiments/dtrace-testing/out/entitlements/EntitlementJail.app.entitlements.txt`
  - `book/experiments/dtrace-testing/out/entitlements/ProbeService_debuggable.xpc.entitlements.txt`
- Entitlements (brittle string witness):
  - `book/experiments/dtrace-testing/out/entitlements/ProbeService_debuggable.entitlements.strings.txt`
- Entitlements (runtime witness):
  - `book/experiments/dtrace-testing/out/entitlements/ProbeService_debuggable.capabilities_snapshot.json`
  - `book/experiments/dtrace-testing/out/entitlements/ProbeService_debuggable.capabilities_snapshot_smoke.json`
  - `book/experiments/dtrace-testing/out/entitlements/ProbeService_debuggable.capabilities_snapshot_idle.json`
  - `book/experiments/dtrace-testing/out/entitlements/ProbeService_debuggable.capabilities_snapshot_interaction.json`
- DTrace capture artifacts:
  - `book/experiments/dtrace-testing/out/meta/dtrace_smoke.stderr`
  - `book/experiments/dtrace-testing/out/meta/dtrace_idle.stderr`
  - `book/experiments/dtrace-testing/out/meta/dtrace_interaction.stderr`
  - `book/experiments/dtrace-testing/out/meta/smoke.json`
  - `book/experiments/dtrace-testing/out/meta/idle.json`
  - `book/experiments/dtrace-testing/out/meta/interaction.json`
  - `book/experiments/dtrace-testing/out/raw/smoke.jsonl` (empty)
  - `book/experiments/dtrace-testing/out/raw/idle.jsonl` (empty)
  - `book/experiments/dtrace-testing/out/raw/interaction.jsonl` (empty)
- Normalized summary:
  - `book/experiments/dtrace-testing/out/normalized/deny_signatures.json`
- Interaction outputs:
  - `book/experiments/dtrace-testing/out/interaction/fs_op_stat.json`
  - `book/experiments/dtrace-testing/out/interaction/fs_op_open_read.json`
  - `book/experiments/dtrace-testing/out/interaction/fs_op_listdir.json`
- Non-system target (for PID-attach control):
  - `book/experiments/dtrace-testing/targets/sleep_loop.c`
  - `book/experiments/dtrace-testing/targets/sleep_loop`
  - `book/experiments/dtrace-testing/out/meta/dtrace_non_system.json`
  - `book/experiments/dtrace-testing/out/meta/dtrace_non_system.stderr`
  - `book/experiments/dtrace-testing/out/meta/dtrace_non_system.stdout`
  - `book/experiments/dtrace-testing/out/meta/dtrace_non_system_sudo.json`
  - `book/experiments/dtrace-testing/out/meta/dtrace_non_system_sudo.stderr`
  - `book/experiments/dtrace-testing/out/meta/dtrace_non_system_sudo.stdout`

## Observations (runtime, partial)
- `ProbeService_debuggable` `capabilities_snapshot` reports `has_get_task_allow=true` and `has_disable_library_validation=true`. This is a runtime witness from the app, not a codesign-backed entitlement dump (partial).
- `fs_op` against `downloads` path-class produced permission-shaped errors (`errno=1`) for `open_read` and `listdir`, while `stat` succeeded. These are runtime outcomes from EntitlementJail’s probe layer, not DTrace syscall witnesses (partial; do not treat as PolicyGraph paths).
- No DTrace syscall or `sandbox_check`/`sandbox_init`/`sandbox_apply` events were captured. Non-sudo runs fail to initialize DTrace (`DTrace requires additional privileges`), while sudo runs either fail to grab the target PID (EntitlementJail + `/bin/sleep`) or reject the syscall probe specification (`syscall::nanosleep`) with SIP-on errors for the non-system `sleep_loop` target (partial; indicates provider suppression rather than confirmed attach success).
- The non-system sudo run used a `sleep_loop` PID captured from the process launch; the PID is ephemeral but matches the intended target in `book/experiments/dtrace-testing/out/meta/dtrace_non_system_sudo.json`.

## Concept mapping (partial)
- Syscall family mapping (planned for DTrace, not observed):
  - `open`/`openat` → `file-read-data` (partial, pending DTrace witness).
  - `stat`/`lstat`/`stat64`/`lstat64` → `file-read-metadata` (partial, pending DTrace witness).
  - `listdir` (via `fs_op`) → `file-read-data` (partial, probe-layer evidence only).
- Filter mapping: path literals from `fs_op` outputs are treated as candidate `path` filter evidence only; no filter ID attribution without decode or additional witnesses.
- EPERM/EACCES remain runtime **decision** outcomes; see `status/EPERM/apply-gate.md` for apply-gate context. No PolicyGraph path is claimed here.

## Blockers / risks
- On this SIP-enabled baseline, the DTrace syscall provider appears suppressed (`invalid probe specifier syscall::nanosleep:entry ... System Integrity Protection is on`) even when running under sudo against a non-system target. This blocks syscall-based JSONL capture for our intended probe set (blocked/partial).
- PID-attach behavior is inconsistent across targets: `failed to grab pid` is observed for EntitlementJail PIDs and `/bin/sleep` under sudo, while the non-system `sleep_loop` run reaches DTrace but fails at provider enablement. Treat PID-attach semantics for non-system binaries as unresolved on this world (partial).
- `ProbeService_debuggable` is short-lived per `run-xpc` call; PIDs change across runs, complicating attachment timing (secondary to the blocked attach).
- `codesign` reports invalid entitlements blobs for these binaries; entitlement extraction is brittle without a stable signer.
- DTrace JSONL path strings are not JSON-escaped; avoid paths with quotes/backslashes when capture is unblocked.
- User-stack capture is not wired into the JSONL output yet; adding a JSON-safe `ustack` encoder is required for callsite grouping.

## Next steps
- Re-run `capture.py` with sudo in a normal Terminal to obtain syscall-level JSONL output.
- Investigate keeping `ProbeService_debuggable` alive (launchd/launchctl) to make `-p` attachment reliable.
- If `sandbox_init`/`sandbox_apply` events appear under DTrace, record return values and `errno` as lifecycle witnesses (high value).
- Re-run the non-system attach test (`targets/sleep_loop`) under sudo to isolate SIP DTrace restrictions vs protected targets.
- If possible, run `dtrace -l -n 'syscall:::entry'` on this host and capture output to confirm provider suppression directly.
