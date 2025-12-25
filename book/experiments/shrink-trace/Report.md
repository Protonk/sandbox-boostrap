# shrink-trace Experiment

## Purpose
- Reproduce and instrument a trace-then-shrink workflow that bootstraps SBPL allow rules from sandbox violations and minimizes the resulting profile.

## Baseline & scope
- Host baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Inputs: upstream `trace.sh`/`shrink.sh`, deterministic fixture `fixtures/sandbox_target.c`, instrumented tracer, and unified log output on this host.
- Out of scope: cross-version claims or promotion into shared mappings until runs are completed and validated.

## Deliverables / expected outcomes
- Output directory with `profile.sb`, `profile.sb.shrunk`, `metrics.tsv`, and per-iteration logs under `out/`.
- A summarized convergence story (iterations, new rules, shrink removals).
- A reproducible run path using `scripts/run_workflow.sh`.

## Plan & execution log
- Ran `scripts/run_workflow.sh` with the dyld seed enabled (`SEED_DYLD=1`), JSON log capture, and per-iteration preflight.
- Iteration 1 logged a deny for `process-exec*` on the fixture binary and appended the allow rule (profile now 16 lines including the seed block).
- Iteration 2 aborted (`sandbox-exec` SIGABRT) with no new deny lines; the trace marked this as `stalled` and emitted a stall bundle.
- Shrink is skipped when trace does not reach `rc==0` (current run stopped at `stalled`).

## Evidence & artifacts
- Current run outputs live under `book/experiments/shrink-trace/out/` (profile, logs, metrics, stdout captures).
- Preflight scan output: `book/experiments/shrink-trace/out/preflight_scan.json`.
- Supplemental `log show` capture for `sandbox-exec`: `book/experiments/shrink-trace/out/log_show_sandbox_exec.txt`.
- Per-iteration preflight outputs are written alongside logs as `book/experiments/shrink-trace/out/logs/iter_<n>_preflight.json`.
- Stall bundle (SIGABRT, no new denies): `book/experiments/shrink-trace/out/stall_iter_2/`.
- Manual abort capture: `book/experiments/shrink-trace/out/stdout.txt`, `book/experiments/shrink-trace/out/stderr.txt`, `book/experiments/shrink-trace/out/exitcode.txt`.
- Crash report (sandbox_target, SIGABRT): `book/experiments/shrink-trace/out/sandbox_target-2025-12-24-173108.ips`.

## Blockers / risks
- Unified log access may be restricted (Full Disk Access or admin context required).
- The return-code stop condition can end tracing early if the target tolerates denies; the instrumented script now records non-zero return codes correctly.
- On this host, `sandbox-exec` aborts (SIGABRT) after the initial allow rule is added, and no additional deny lines appear. This stalls the trace loop and prevents shrink from running successfully.
- The captured crash report (`.ips`) is a SIGABRT for `sandbox_target` but lacks a usable backtrace; dyld process info is missing, so abort location is still unresolved.

## Next steps
- Run `scripts/run_workflow.sh` and capture outputs.
- Summarize metrics and note any blocked or brittle behavior.
