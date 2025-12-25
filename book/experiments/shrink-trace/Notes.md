# Notes

- Initial scaffolding created; no runs yet.
- Ran `scripts/run_workflow.sh`; trace produced a 4-line profile but `sandbox-exec` aborted on iteration 2 (SIGABRT) and shrink could not execute with the traced profile. The original `work/` outputs were cleaned during migration to `out/`.
- Verified `sandbox-exec` works with a permissive profile (`(allow default)`), and `sandbox_target` runs to completion under that profile.
- Migrated outputs to `out/` (overwrite on each run) and removed prior `work/` runs.
- New run after migration: trace advanced to iteration 4 but failed with `sandbox-exec` SIGABRT on iteration 2 and later a profile parse error from an invalid network rule (`local ip "remote:*:2000"`). Outputs are in `book/experiments/shrink-trace/out/`.
- Captured preflight scan output to `book/experiments/shrink-trace/out/preflight_scan.json` and `log show` output to `book/experiments/shrink-trace/out/log_show_sandbox_exec.txt`.
- Hooked preflight scans into `trace_instrumented.sh` (per-iteration) and `run_workflow.sh` (trace profile before shrink).
- Updated trace parsing to use JSON-style logs with a `log show` fallback and added a dyld seed block.
- Current run (`SEED_DYLD=1`) stalls on SIGABRT in iteration 2; stall bundle in `book/experiments/shrink-trace/out/stall_iter_2/`.
- Manual abort capture saved to `book/experiments/shrink-trace/out/stdout.txt`, `book/experiments/shrink-trace/out/stderr.txt`, and `book/experiments/shrink-trace/out/exitcode.txt` (exit code 134).
- Copied latest crash report to `book/experiments/shrink-trace/out/sandbox_target-2025-12-24-173108.ips`.
