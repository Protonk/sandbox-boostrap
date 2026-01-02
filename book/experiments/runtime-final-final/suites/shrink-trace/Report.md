# shrink-trace Experiment

## Purpose

- Reproduce a trace-then-shrink workflow that bootstraps SBPL allow rules from sandbox denials and then minimizes the profile.
- Tie the workflow to host-bound evidence for `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

## Baseline & scope

- Host baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Scope: host-local behavior only; no cross-version claims.
- Status: experiment evidence (partial). No promotion to shared mappings yet.

## How we learned it (methods + runs)

- Trace phase: `scripts/trace_instrumented.sh` captures unified log denials, appends allow rules, and enforces repeatable success (`SUCCESS_STREAK`).
- Shrink phase: `scripts/shrink_instrumented.sh` removes rules only if fresh + repeat runs both succeed.
- Preflight: `book/tools/preflight/preflight.py scan` is used before shrink to avoid known apply-gates.
- Fixtures: `sandbox_target`, `sandbox_net_required`, `sandbox_spawn`, and `sandbox_min`.
- Example runs are captured under:
  - `book/experiments/runtime-final-final/suites/shrink-trace/out/trace_baseline`
  - `book/experiments/runtime-final-final/suites/shrink-trace/out/trace_net_required`
  - `book/experiments/runtime-final-final/suites/shrink-trace/out/trace_spawn`
  - `book/experiments/runtime-final-final/suites/shrink-trace/out/trace_min` (with `SEED_DYLD=0`)
  - `book/experiments/runtime-final-final/suites/shrink-trace/out/shrink_twostate`
  - `book/experiments/runtime-final-final/suites/shrink-trace/out/shrink_net_required`
  - `book/experiments/runtime-final-final/suites/shrink-trace/out/shrink_spawn`
  - `book/experiments/runtime-final-final/suites/shrink-trace/out/shrink_unused` (plus manual shrink)
- A run matrix across fixtures and knobs is summarized in `book/experiments/runtime-final-final/suites/shrink-trace/out/matrix/summary.json` with per-run outputs under `book/experiments/runtime-final-final/suites/shrink-trace/out/matrix`.

## What we learned (host-bound, partial)

- **Trace convergence is achievable on this host** for baseline, network-required, subprocess, and minimal loader fixtures using the repeatable-success contract; see `book/experiments/runtime-final-final/suites/shrink-trace/out/trace_*/phases/trace/metrics.jsonl`.
- **Shrink preserves first-run and repeat-run requirements** when gated by the two-state check; see `book/experiments/runtime-final-final/suites/shrink-trace/out/shrink_twostate/phases/shrink/validation/post_shrink_fresh.json` and `book/experiments/runtime-final-final/suites/shrink-trace/out/shrink_twostate/phases/shrink/validation/post_shrink_repeat.json`.
- **Required network access is retained** through shrink in the network-required fixture (`network-outbound` stays present); see `book/experiments/runtime-final-final/suites/shrink-trace/out/shrink_net_required/profiles/shrunk.sb`.
- **Subprocess execution rules are preserved** (`process-fork` and `process-exec*` for `/usr/bin/id`) in the spawn fixture; see `book/experiments/runtime-final-final/suites/shrink-trace/out/shrink_spawn/profiles/shrunk.sb`.
- **Manual shrink removes unused rules** when they are appended post-trace; see `book/experiments/runtime-final-final/suites/shrink-trace/out/shrink_unused/phases/shrink/stdout_manual.txt`.
- **Loader boundary runs can abort early** under `SEED_DYLD=0` but still converge after rule growth; see `book/experiments/runtime-final-final/suites/shrink-trace/out/trace_min/phases/trace/stdout.txt` and `book/experiments/runtime-final-final/suites/shrink-trace/out/trace_min/profiles/shrunk.sb`.
- **Matrix results show knob sensitivity** (trace sizes and bad-rule counts vary with dyld import and network rule mode); see `book/experiments/runtime-final-final/suites/shrink-trace/out/matrix/summary.json`.

## Where we failed or saw brittleness

- **Matrix timeouts:** the matrix runner timed out twice before completing with a longer timeout; results were still captured in `book/experiments/runtime-final-final/suites/shrink-trace/out/matrix/summary.json`.
- **Early `no_new_rules` stops:** some runs ended `no_new_rules` on the first attempt but converged on rerun, indicating log capture or environmental noise sensitivity.
- **Loader aborts:** removing `import "dyld-support.sb"` during shrink can trigger `SIGABRT`, which is treated as evidence that the import is required on this host rather than a safe removal.
- **Network drop mode:** in the matrix, `NETWORK_RULES=drop` prevents the required-network fixture from converging (`trace_status=no_new_rules`), showing that drop mode cannot satisfy that workload.

## Evidence & artifacts

- Example run artifacts: `book/experiments/runtime-final-final/suites/shrink-trace/out/trace_*` and `book/experiments/runtime-final-final/suites/shrink-trace/out/shrink_*`.
- Run manifests: `book/experiments/runtime-final-final/suites/shrink-trace/out/**/run.json`.
- Manual shrink run: `book/experiments/runtime-final-final/suites/shrink-trace/out/shrink_unused/phases/shrink/stdout_manual.txt`.
- Matrix summary: `book/experiments/runtime-final-final/suites/shrink-trace/out/matrix/summary.json` (per-run outputs under `book/experiments/runtime-final-final/suites/shrink-trace/out/matrix`).
- Trace status markers: `book/experiments/runtime-final-final/suites/shrink-trace/out/**/phases/trace/status.json`.
- Lint output: `book/experiments/runtime-final-final/suites/shrink-trace/out/**/phases/trace/validation/lint.txt`, `book/experiments/runtime-final-final/suites/shrink-trace/out/**/phases/shrink/validation/lint.txt`.

## What we plan to learn next (and why)

- **Log coverage vs PID scoping:** compare `DENY_SCOPE=pid` with `DENY_SCOPE=all` to quantify incidental denies and separate signal from noise. This teaches how much of the deny surface is attributable to child processes or ambient system activity.
- **Dyld import minimality:** test which dyld-support allowances are strictly required for minimal launch. This bounds loader dependencies that must exist before user code runs.
- **Network parsing robustness:** characterize which network deny shapes still end up in `bad_rules.txt` under realistic workloads. This teaches which SBPL network filters are actually usable on this host.
- **Repeatability under different streaks:** vary `SUCCESS_STREAK` to quantify convergence stability. This teaches how sensitive deny-based bootstrapping is to log timing and non-determinism.

## Notes on status

- Findings here are host-bound and partial; they are grounded in `out/` artifacts but are not promoted into shared mappings.
