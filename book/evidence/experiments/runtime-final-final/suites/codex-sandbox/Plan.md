# codex-sandbox (Plan)

## Purpose

Detect whether the Codex harness is sandboxed using a small, deterministic sensor set, and separate harness gating from policy outcomes.

## Baseline and scope

- Host baseline: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5.
- No SIP/TCC or host changes.
- Variation: normal harness vs elevated harness (sandboxed vs unsandboxed).
- Outputs live under `book/evidence/experiments/runtime-final-final/suites/codex-sandbox/out/codex-sandbox/`.

## Sensors (S0-S5)

S0. **Self sandboxed** (preflight, scenario)
- `sandbox_check(getpid(), NULL, ...)`.
- Threshold: rc=1 => sandboxed, rc=0 => not sandboxed.

S1. **Mach-lookup preflight** (preflight, scenario)
- `sandbox_check(getpid(), "mach-lookup", filter, service_name)`.
- Service: `com.yourteam.policy-witness.ProbeService_minimal`.
- Filter constant: prefer `SANDBOX_FILTER_XPC_SERVICE_NAME`, fallback to `SANDBOX_FILTER_GLOBAL_NAME`.
- If filter constants are unavailable, use unfiltered `mach-lookup` fallback and record limitation.

S2. **Bootstrap sentinel** (bootstrap, scenario)
- `bootstrap_look_up` on `com.apple.cfprefsd.agent`.
- Threshold: kr=1100 => bootstrap constrained.

S3. **Sentinel XPC probe** (bootstrap or operation, scenario)
- `policy-witness xpc run --profile minimal fs_op --op stat --path-class tmp`.
- Threshold: `xpc_error` + `xpc:openSession_failed` + error 159 => harness blocks service lookup.

S4. **SBPL apply heuristic** (apply, baseline)
- `book/tools/sbpl/wrapper/wrapper --preflight enforce --sbpl allow_all.sb -- /usr/bin/true`.
- Threshold: apply-stage EPERM with preflight ok => likely preexisting sandbox.

S5. **Log corroboration** (observer, scenario)
- `log show --last 10s` with sandbox predicate.
- Threshold: `deny(1) mach-lookup <service>` or `deny(1) forbidden-sandbox-reinit`.
- If `log show` fails with `Cannot run while sandboxed`, treat as supporting signal.

## Runs

- Pass A: normal harness (sandboxed).
- Pass B: elevated harness (unsandboxed).
- Record each run under `out/codex-sandbox/<run_id>/` with a `manifest.json`.

## Deliverables

- `Report.md` with sensor definitions, run evidence, reliability notes, and outcome summary.
- `Notes.md` with commands and run IDs.
- `codex_sandbox.py` runner to reproduce S0-S5.
