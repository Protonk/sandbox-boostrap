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
- Ran `scripts/run_workflow.sh` with defaults (`SEED_DYLD=1`, `IMPORT_DYLD_SUPPORT=1`, `NETWORK_RULES=drop`).
- Iteration counts: 3 total; iteration 1 added 12 rules, iteration 2 added 5 rules, iteration 3 returned `rc=0` with 0 new rules (`metrics.tsv`).
- `sandbox_min` exited 0, so the profile parses and execs a trivial target when fixture execs are allowed.
- Preflight scan for the traced profile completed successfully before shrink.
- Shrink failed at the initial “full sandbox” check: `open(out/hello.txt)` was denied, so the shrink step did not proceed.
- Network denies were dropped into `bad_rules.txt` rather than rewritten (avoids the earlier rc=65 parse failures).

## Evidence & artifacts
- Current run outputs live under `book/experiments/shrink-trace/out/` (profile, logs, metrics, stdout captures).
- Preflight scan output: `book/experiments/shrink-trace/out/preflight_scan.json`.
- Per-iteration preflight outputs are written alongside logs as `book/experiments/shrink-trace/out/logs/iter_<n>_preflight.json`.
- Trace status: `book/experiments/shrink-trace/out/trace_status.txt`.
- `sandbox_min` diagnostic outputs: `book/experiments/shrink-trace/out/sandbox_min_stdout.txt`, `book/experiments/shrink-trace/out/sandbox_min_stderr.txt`, `book/experiments/shrink-trace/out/sandbox_min_exitcode.txt`.
- Dropped network denies: `book/experiments/shrink-trace/out/bad_rules.txt`.
- Shrink failure output: `book/experiments/shrink-trace/out/shrink_stdout.txt`.

## Blockers / risks
- Unified log access may be restricted (Full Disk Access or admin context required).
- The return-code stop condition can end tracing early if the target tolerates denies; the instrumented script now records non-zero return codes correctly.
- Shrink fails because the traced profile allows `file-write-create` for `out/hello.txt` but not `file-write-data`, so a subsequent run on an existing file is denied.
- Network denies are currently dropped by default (`NETWORK_RULES=drop`) to avoid malformed rules; enabling parsed network rules remains brittle and needs validation.

## Next steps
- Decide whether to: (a) add a fixture step that forces `file-write-data` denials in trace, or (b) treat this as a known shrink confounder and document it explicitly.
- Re-run with `NETWORK_RULES=parsed` once rule normalization is validated (optional).
