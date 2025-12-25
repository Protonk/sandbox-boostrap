# shrink-trace experiment

## Purpose
- Reproduce a trace-then-shrink workflow that bootstraps SBPL allow rules from sandbox violations, then minimizes the profile.
- Make the workflow observable by capturing per-iteration logs and metrics (deny lines, new rules, stop reason).
- Stay host-bound to `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` and treat outputs as experiment-local unless promoted.

## Background (external context; substrate-only)
These references are external documentation and not host witnesses. Treat them as substrate-only context for why the workflow exists.
- `sandbox-exec` is marked DEPRECATED in the man page, and profiles can be supplied via `-f` (profile file), `-n` (named profile), or `-p` (profile string). See `sandbox-exec(1)` for the exact CLI surface. [1]
- Sandbox violations are observable via unified logs, and a practical predicate includes `com.apple.sandbox.reporting` in addition to `/Sandbox` sender paths. [2]
- SBPL is Scheme-like, typically starts with `(version 1)` and `(deny default)`, and macOS ships many profiles (for example under `/System/Library/Sandbox/Profiles`). [3]
- Older guidance documents a `(trace ...)` directive for bootstrapping profiles, but it is not a current general-purpose solution. This motivates log-based tracing scripts like the upstream `trace.sh`. [4]

## Files in this experiment
- `book/experiments/shrink-trace/upstream/trace.sh` - upstream tracer (verbatim).
- `book/experiments/shrink-trace/upstream/shrink.sh` - upstream shrinker (verbatim).
- `book/experiments/shrink-trace/upstream/readme.md` - upstream notes (verbatim).
- `book/experiments/shrink-trace/fixtures/sandbox_target.c` - deterministic workload fixture.
- `book/experiments/shrink-trace/fixtures/sandbox_min.c` - minimal fixture to test dyld/bootstrap.
- `book/experiments/shrink-trace/scripts/build_fixture.sh` - build the fixture.
- `book/experiments/shrink-trace/scripts/extract_denies.py` - parse JSON-style logs to extract deny lines by PID.
- `book/experiments/shrink-trace/scripts/extract_sandbox_messages.py` - extract sandbox-related event messages from JSON logs.
- `book/experiments/shrink-trace/scripts/trace_instrumented.sh` - instrumented tracer with metrics.
- `book/experiments/shrink-trace/scripts/run_workflow.sh` - build, trace, shrink, verify.
- `book/experiments/shrink-trace/scripts/summarize_metrics.sh` - summarize metrics from a run.
- `book/experiments/shrink-trace/out/` - run outputs (overwritten on each run).

## Quickstart
Prereqs (host-bound):
- macOS with `sandbox-exec` available (deprecated but often present). [1]
- `log stream` available and readable for your terminal session. [2]
- If `log stream` yields no denies, try running in an admin context or grant Full Disk Access to your terminal.

Run the workflow from `book/experiments/shrink-trace`:
```
./scripts/run_workflow.sh
```
Then summarize metrics:
```
./scripts/summarize_metrics.sh
```

## Outputs
Each run writes to `book/experiments/shrink-trace/out/` (overwriting any previous output) with:
- `profile.sb` - traced profile.
- `profile.sb.shrunk` - minimized profile.
- `metrics.tsv` - iteration metrics.
- `logs/iter_<n>.log` - per-iteration unified log output (JSON).
- `logs/iter_<n>_log_show.json` - log show fallback output (only when log stream yields no denies).
- `logs/iter_<n>_stdout.txt` - per-iteration sandboxed stdout.
- `logs/iter_<n>_stderr.txt` - per-iteration sandboxed stderr.
- `logs/iter_<n>_pid.txt` - PID of the `sandbox-exec` wrapper for that iteration.
- `logs/iter_<n>_preflight.json` - per-iteration preflight scan output.
- `trace_stdout.txt` - trace output.
- `shrink_stdout.txt` - shrink output.
- `preflight_scan.json` - preflight scan of the traced profile before shrink.
- `trace_status.txt` - trace stop reason (`success`, `no_new_rules`, `stalled`, `preflight_failed`, or `profile_invalid`).
- `stall_iter_<n>/` - bundle created when the trace stalls on a signal with no observed denies (includes logs, stderr, and any crash report found).
- `stall_iter_<n>/sandbox_messages.txt` - sandbox-related event messages collected from the stall logs.
- `profile_invalid_iter_<n>/` - bundle created when `sandbox-exec` exits with rc=65 (parse failure); includes `bad_rules.txt` and `last_appended_rule.txt`.
- `bad_rules.txt` - rules rejected because they broke profile parsing.
- `last_appended_rule.txt` - last rule appended before a failure.
- `dyld.log` - dyld debug log (when `DYLD_LOG=1`).
- `sandbox_min_stdout.txt` - stdout from the minimal fixture check.
- `sandbox_min_stderr.txt` - stderr from the minimal fixture check.
- `sandbox_min_exitcode.txt` - exit code from the minimal fixture check.

## Interpreting results
1) Trace convergence:
- Count iterations until stop.
- Total allow rules appended.
- Stop reason: `return_code == 0` vs no new rules.

2) Noise vs necessity:
- `denies_seen` per iteration.
- `new_rules` per iteration.
- Rules removed by shrink (see `shrink_stdout.txt`).

3) Profile shape:
- Count rule prefixes in `profile.sb` (rough categorizer):
  - `file-*`
  - `network-*`
  - `mach-lookup`
  - `sysctl-*`
  Example (run inside a run dir):
  - `grep -E '^\(allow file-' profile.sb | wc -l`
  - `grep -E '^\(allow network-' profile.sb | wc -l`
  - `grep -E '^\(allow mach-lookup' profile.sb | wc -l`
  - `grep -E '^\(allow sysctl-' profile.sb | wc -l`

4) Correctness check:
- `sandbox-exec -f profile.sb.shrunk sandbox_target` returns 0.

## Workflow details (upstream behavior)
- `trace.sh` initializes a profile with:
  ```
  (version 1)
  (deny default)
  ```
  then runs the program under `sandbox-exec`, captures `deny` log lines, and appends `(allow ...)` rules derived from those lines.
- It stops when either the program returns 0 or no new rules are added.
- `shrink.sh` removes profile lines from bottom to top, keeping a deletion if the command still succeeds. It refuses to delete explicit `(deny ...)` rules even if deletion would still succeed.
- The instrumented tracer in `scripts/trace_instrumented.sh` keeps the upstream CLI contract but adds per-iteration logs, metrics, a broader log predicate, and avoids `killall` side effects.

## Troubleshooting and confounders
1) Log predicate mismatches
- Upstream uses: `((processID == 0) AND (senderImagePath CONTAINS '/Sandbox'))`.
- A broader predicate includes `subsystem == "com.apple.sandbox.reporting"`. [2]
- If denies are missing, use the instrumented script or adjust the predicate.

2) Return-code-as-success is leaky
- If the program tolerates denied operations and still exits 0, tracing can stop early.
- You may need to harden the fixture or adjust the success code.

3) Temporary or random filenames
- If required outputs use random names, the tracer will keep producing new literals.
- Convert `(literal "...")` to a directory-wide rule such as `(subpath "...")` when needed.

4) Subprocesses
- The workflow does not follow `exec*()` subprocesses.
- Trace subprocesses separately and combine profiles via `(import ...)`.

5) Side effects in upstream `trace.sh`
- Upstream ends with `killall $PROGRAM_NAME` and `killall log`.
- Avoid running it unchanged in environments where killing `log` is disruptive.

## Extensions
- Allow arguments (not just a bare executable name) in the tracing and shrinking scripts.
- Add a rule-shape summary script (prefix counts, unique ops) alongside `summarize_metrics.sh`.
- Record the stop reason explicitly in `metrics.tsv` (rc vs no-new-rules).
- Add a small harness for repeated runs to compare convergence stability.

## Variants
- `SEED_DYLD=1` (default) adds a small loader/dyld seed block to the initial profile to help the target reach deny emission.
- `SEED_DYLD=0` disables the seed for the minimal `(version 1)` + `(deny default)` baseline.
- `DENY_SIGSTOP=1` replaces `(deny default)` with `(deny default (with send-signal SIGSTOP))` to stop on first violation for debugger attach.
- `IMPORT_DYLD_SUPPORT=1` (default) imports `dyld-support.sb` when present under `/System/Library/Sandbox/Profiles/`.
- `DYLD_LOG=1` enables dyld logging to `dyld.log` in the output directory.
- `ALLOW_FIXTURE_EXEC=1` (default) allows `process-exec*` and `file-read-metadata` for the output directory so `sandbox_min` is executable.
- `NETWORK_RULES=drop` (default) drops network denies; `NETWORK_RULES=coarse` emits `(allow network-*)` without filters; `NETWORK_RULES=parsed` emits `(remote ip)` or `(local ip)` with normalization.

[1]: https://man.freebsd.org/cgi/man.cgi?manpath=macOS+14.8&query=sandbox-exec&sektion=1 "sandbox-exec(1)"
[2]: https://chromium.googlesource.com/chromium/src/%2B/8073c7e0afcb/docs/mac/sandbox_debugging.md "Sandbox Debugging"
[3]: https://chromium.googlesource.com/chromium/src/%2B/HEAD/sandbox/mac/seatbelt_sandbox_design.md "Mac Sandbox V2 Design Doc"
[4]: https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles "GitHub - s7ephen/OSX-Sandbox--Seatbelt--Profiles"
